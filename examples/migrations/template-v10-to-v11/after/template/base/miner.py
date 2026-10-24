# The MIT License (MIT)
# Copyright © 2023 Yuma Rao

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


import logging
import argparse

from taowire import Miner as KitMiner
from taowire.compat import Axon, Metagraph

from template.base.neuron import BaseNeuron
from template.utils.config import add_miner_args


class BaseMinerNeuron(BaseNeuron):
    """
    Base class for Bittensor miners.
    """

    neuron_type: str = "MinerNeuron"

    @classmethod
    def add_args(cls, parser: argparse.ArgumentParser):
        super().add_args(parser)
        add_miner_args(cls, parser)

    def __init__(self, config=None, miner: KitMiner = None):
        super().__init__(config=config)

        # Warn if allowing incoming requests from anyone.
        if not self.config.blacklist.force_validator_permit:
            logging.warning(
                "You are allowing non-validators to send requests to your miner. This is a security risk."
            )
        if self.config.blacklist.allow_non_registered:
            logging.warning(
                "You are allowing non-registered entities to send requests to your miner. This is a security risk."
            )

        # The axon handles request processing, allowing validators to send this miner requests.
        # TaoWire verifies every request and applies its caller policy before blacklist().
        self.axon = Axon(miner=miner or KitMiner.from_env())
        self.metagraph = Metagraph.of_miner(self.axon.miner)

        # Attach determiners which functions are called when servicing a request.
        logging.info(f"Attaching forward function to miner axon.")
        self.axon.attach(
            forward_fn=self.forward,
            blacklist_fn=self.blacklist,
            priority_fn=self.priority,
        )
        logging.info(f"Axon created: {self.axon}")

    def run(self):
        """
        Starts the miner: TaoWire checks registration, publishes the axon
        (TW_EXTERNAL_IP), keeps the metagraph fresh and serves until SIGTERM.
        """
        self.axon.serve(netuid=self.config.netuid)
        self.axon.start()
