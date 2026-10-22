# The MIT License (MIT)
# Copyright © 2023 Yuma Rao
# TODO(developer): Set your name
# Copyright © 2023 <your name>

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the “Software”), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial portions of
# the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

import os
import copy
import numpy as np
import asyncio
import argparse
import logging
from typing import List
from traceback import print_exception

from tensorwire import RequestSigner, ValidatorSettings
from tensorwire.auth.keys import load_hotkey
from tensorwire.chain.gateway import BittensorGateway
from tensorwire.chain.metagraph_cache import MetagraphCache
from tensorwire.compat import Dendrite, Metagraph, weights
from tensorwire.validator.weights import WeightScheduler

from template.base.neuron import BaseNeuron
from template.utils.config import add_validator_args


class BaseValidatorNeuron(BaseNeuron):
    """
    Base class for Bittensor validators. Your validator should inherit from this class.
    """

    neuron_type: str = "ValidatorNeuron"

    @classmethod
    def add_args(cls, parser: argparse.ArgumentParser):
        super().add_args(parser)
        add_validator_args(cls, parser)

    def __init__(
        self,
        config=None,
        *,
        settings=None,
        hotkey=None,
        gateway=None,
        metagraph_source=None,
        transport=None,
    ):
        super().__init__(config=config)

        # TensorWire parts: hotkey only (TW_WALLET_*), chain gateway, metagraph cache.
        self.settings = settings or ValidatorSettings.from_env()
        s = self.settings
        hotkey = hotkey or load_hotkey(s.wallet_path, s.wallet_name, s.wallet_hotkey)
        signer = RequestSigner(hotkey)
        self.gateway = gateway or BittensorGateway.from_settings(s, hotkey)
        self.metagraph_source = metagraph_source or MetagraphCache.from_settings(
            self.gateway, s
        )
        self.metagraph = Metagraph(self.metagraph_source)

        # Dendrite lets us send messages to other nodes (axons) in the network.
        self.dendrite = Dendrite(
            signer, timeout_s=self.config.neuron.timeout, transport=transport
        )
        logging.info(f"Dendrite: {self.dendrite}")

        # v11 SetWeights normalises and quantises; the scheduler follows the chain's rate limit.
        self.weight_setter = WeightScheduler(
            self.gateway,
            self.config.netuid,
            signer.hotkey_ss58,
            min_interval_blocks=self.config.neuron.epoch_length,
            version_key=self.spec_version,
            mechid=s.mechid,
        )

        # Set up initial scoring weights for validation
        logging.info("Building validation weights.")
        self.hotkeys = []
        self.scores = np.zeros(0, dtype=np.float32)
        if not os.path.exists(self.config.neuron.full_path + "/state.npz"):
            self.save_state()

        self.should_exit: bool = False

    async def start(self):
        """Connect to the chain, load the metagraph and check registration."""
        await self.gateway.connect()
        await self.metagraph_source.start()
        if self.dendrite.hotkey not in self.metagraph.hotkeys:
            raise RuntimeError(
                f"hotkey {self.dendrite.hotkey} is not registered on netuid "
                f"{self.config.netuid}; register it with btcli first"
            )
        self.resync_metagraph()

    async def stop(self):
        """Close the dendrite, the metagraph cache and the chain connection."""
        await self.dendrite.aclose()
        await self.metagraph_source.stop()
        await self.gateway.close()

    async def concurrent_forward(self):
        coroutines = [
            self.forward()
            for _ in range(self.config.neuron.num_concurrent_forwards)
        ]
        await asyncio.gather(*coroutines)

    async def step_once(self):
        """One validator step: query and score, then resync and set weights."""
        logging.info(f"step({self.step}) block({self.metagraph.block})")
        await self.concurrent_forward()
        await self.sync()
        self.step += 1

    async def sync(self):
        """Resync scores with the metagraph, set weights when due, save state."""
        self.resync_metagraph()
        if self.should_set_weights():
            await self.set_weights()
        self.save_state()

    def should_set_weights(self) -> bool:
        # Don't set weights on initialization or if disabled; the scheduler
        # follows the chain's weights rate limit and neuron.epoch_length.
        return self.step > 0 and not self.config.neuron.disable_set_weights

    def run(self):
        """
        Runs the validator until interrupted: each step queries miners, scores
        the responses and, when the chain allows it, sets weights.
        """
        asyncio.run(self._run())

    async def _run(self):
        await self.start()
        logging.info(f"Validator starting at block: {self.metagraph.block}")
        try:
            while not self.should_exit:
                await self.step_once()
        except KeyboardInterrupt:
            logging.info("Validator killed by keyboard interrupt.")
        except Exception as err:
            logging.error(f"Error during validation: {str(err)}")
            logging.debug(
                str(print_exception(type(err), err, err.__traceback__))
            )
        finally:
            await self.stop()

    async def set_weights(self):
        """
        Sets the validator weights to the metagraph hotkeys based on the scores it has received from the miners. The weights determine the trust and incentive level the validator assigns to miner nodes on the network.
        """

        # Check if self.scores contains any NaN values and log a warning if it does.
        if np.isnan(self.scores).any():
            logging.warning(
                f"Scores contain NaN values. This may be due to a lack of responses from miners, or a bug in your reward functions."
            )

        # Calculate the average reward for each uid across non-zero values.
        # Replace any NaN values with 0.
        # Compute the norm of the scores
        norm = np.linalg.norm(self.scores, ord=1, axis=0, keepdims=True)

        # Check if the norm is zero or contains NaN values
        if np.any(norm == 0) or np.isnan(norm).any():
            norm = np.ones_like(norm)  # Avoid division by zero or NaN

        # Compute raw_weights safely
        raw_weights = np.nan_to_num(self.scores / norm)

        logging.debug(f"raw_weights {raw_weights}")
        decision = await self.weight_setter.maybe_submit(
            weights.to_mapping(self.metagraph.uids, raw_weights),
            self.metagraph.snapshot(),
        )
        if decision.submitted:
            logging.info("set_weights on chain successfully (commit included)!")
        else:
            logging.info(f"set_weights: {decision.reason}")

    def resync_metagraph(self):
        """Resets the scores of UIDs whose hotkey changed and resizes them to the metagraph."""
        logging.info("resync_metagraph()")
        hotkeys = self.metagraph.hotkeys
        if hotkeys == self.hotkeys:
            return

        logging.info(
            "Metagraph updated, re-syncing hotkeys, dendrite pool and moving averages"
        )
        # Zero out all hotkeys that have been replaced.
        for uid, hotkey in enumerate(self.hotkeys):
            if uid < len(hotkeys) and hotkey != hotkeys[uid]:
                self.scores[uid] = 0  # hotkey has been replaced

        # Check to see if the metagraph has changed size.
        # If so, we need to add new hotkeys and moving averages.
        if len(self.scores) != len(hotkeys):
            # Update the size of the moving average scores.
            new_scores = np.zeros((len(hotkeys)), dtype=np.float32)
            copy_len = min(len(self.scores), len(hotkeys))
            new_scores[:copy_len] = self.scores[:copy_len]
            self.scores = new_scores

        # Update the hotkeys.
        self.hotkeys = copy.deepcopy(hotkeys)

    def update_scores(self, rewards: np.ndarray, uids: List[int]):
        """Performs exponential moving average on the scores based on the rewards received from the miners."""

        # Check if rewards contains NaN values.
        if np.isnan(rewards).any():
            logging.warning(f"NaN values detected in rewards: {rewards}")
            # Replace any NaN values in rewards with 0.
            rewards = np.nan_to_num(rewards, nan=0)

        # Ensure rewards is a numpy array.
        rewards = np.asarray(rewards)

        # Check if `uids` is already a numpy array and copy it to avoid the warning.
        if isinstance(uids, np.ndarray):
            uids_array = uids.copy()
        else:
            uids_array = np.array(uids)

        # Handle edge case: If either rewards or uids_array is empty.
        if rewards.size == 0 or uids_array.size == 0:
            logging.info(f"rewards: {rewards}, uids_array: {uids_array}")
            logging.warning(
                "Either rewards or uids_array is empty. No updates will be performed."
            )
            return

        # Check if sizes of rewards and uids_array match.
        if rewards.size != uids_array.size:
            raise ValueError(
                f"Shape mismatch: rewards array of shape {rewards.shape} "
                f"cannot be broadcast to uids array of shape {uids_array.shape}"
            )

        # Compute forward pass rewards, assumes uids are mutually exclusive.
        # shape: [ metagraph.n ]
        scattered_rewards: np.ndarray = np.zeros_like(self.scores)
        scattered_rewards[uids_array] = rewards
        logging.debug(f"Scattered rewards: {rewards}")

        # Update scores with rewards produced by this step.
        # shape: [ metagraph.n ]
        alpha: float = self.config.neuron.moving_average_alpha
        self.scores: np.ndarray = (
            alpha * scattered_rewards + (1 - alpha) * self.scores
        )
        logging.debug(f"Updated moving avg scores: {self.scores}")

    def save_state(self):
        """Saves the state of the validator to a file."""
        logging.info("Saving validator state.")

        # Save the state of the validator to file.
        np.savez(
            self.config.neuron.full_path + "/state.npz",
            step=self.step,
            scores=self.scores,
            hotkeys=self.hotkeys,
        )

    def load_state(self):
        """Loads the state of the validator from a file."""
        logging.info("Loading validator state.")

        # Load the state of the validator from file.
        state = np.load(self.config.neuron.full_path + "/state.npz")
        self.step = state["step"]
        self.scores = state["scores"]
        self.hotkeys = list(state["hotkeys"])
