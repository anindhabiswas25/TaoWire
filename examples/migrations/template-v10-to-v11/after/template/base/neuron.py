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

import copy

import logging
from abc import ABC, abstractmethod

from taowire.compat import Synapse

from template.utils.config import check_config, add_args, config
from template import __spec_version__ as spec_version


class BaseNeuron(ABC):
    """
    Base class for Bittensor miners. This class is abstract and should be inherited by a subclass. It contains the core logic for all neurons; validators and miners.

    On TaoWire the kit loads the hotkey (never the coldkey), connects to the
    chain, keeps the metagraph fresh, checks registration and publishes the
    axon; settings come from TW_* variables. This class keeps the template's
    own config (neuron.*, blacklist.*).
    """

    neuron_type: str = "BaseNeuron"

    @classmethod
    def check_config(cls, config):
        check_config(cls, config)

    @classmethod
    def add_args(cls, parser):
        add_args(cls, parser)

    @classmethod
    def config(cls):
        return config(cls)

    spec_version: int = spec_version

    def __init__(self, config=None):
        self.config = config or self.config()
        self.check_config(self.config)

        # If a gpu is required, set the device to cuda:N (e.g. cuda:0)
        self.device = self.config.neuron.device

        # Log the configuration for reference.
        logging.info(self.config)
        self.step = 0

    @abstractmethod
    async def forward(self, synapse: Synapse) -> Synapse:
        ...

    @abstractmethod
    def run(self):
        ...

    def save_state(self):
        logging.debug(
            "save_state() not implemented for this neuron. You can implement this function to save model checkpoints or other useful data."
        )

    def load_state(self):
        logging.debug(
            "load_state() not implemented for this neuron. You can implement this function to load model checkpoints or other useful data."
        )
