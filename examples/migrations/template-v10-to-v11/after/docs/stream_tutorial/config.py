import bittensor as bt
from tensorwire.compat import Axon
import argparse
import os


def check_config(cls, config: "bt.Config"):
    Axon.check_config(config)
    # TW-MIGRATE: TWM025 remove it: the kit configures logging (TW_LOG_LEVEL); use the standard logging module for anything else
    bt.logging.check_config(config)
    full_path = os.path.expanduser(
        "{}/{}/{}/{}".format(
            config.logging.logging_dir,
            config.wallet.get("name", bt.defaults.wallet.name),
            config.wallet.get("hotkey", bt.defaults.wallet.hotkey),
            config.miner.name,
        )
    )
    config.miner.full_path = os.path.expanduser(full_path)
    if not os.path.exists(config.miner.full_path):
        os.makedirs(config.miner.full_path)


def get_config() -> "bt.Config":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--axon.port", type=int, default=8098, help="Port to run the axon on."
    )
    # Subtensor network to connect to
    parser.add_argument(
        "--subtensor.network",
        default="finney",
        help="Bittensor network to connect to.",
    )
    # Chain endpoint to connect to
    parser.add_argument(
        "--subtensor.chain_endpoint",
        default="wss://entrypoint-finney.opentensor.ai:443",
        help="Chain endpoint to connect to.",
    )
    # Adds override arguments for network and netuid.
    parser.add_argument(
        "--netuid", type=int, default=1, help="The chain subnet uid."
    )

    parser.add_argument(
        "--miner.root",
        type=str,
        help="Trials for this miner go in miner.root / (wallet_cold - wallet_hot) / miner.name ",
        default="~/.bittensor/miners/",
    )
    parser.add_argument(
        "--miner.name",
        type=str,
        help="Trials for this miner go in miner.root / (wallet_cold - wallet_hot) / miner.name ",
        default="Bittensor Miner",
    )

    # Run config.
    parser.add_argument(
        "--miner.blocks_per_epoch",
        type=str,
        help="Blocks until the miner repulls the metagraph from the chain",
        default=100,
    )

    # Switches.
    parser.add_argument(
        "--miner.no_serve",
        action="store_true",
        help="If True, the miner doesnt serve the axon.",
        default=False,
    )
    parser.add_argument(
        "--miner.no_start_axon",
        action="store_true",
        help="If True, the miner doesnt start the axon.",
        default=False,
    )

    # Mocks.
    parser.add_argument(
        "--miner.mock_subtensor",
        action="store_true",
        help="If True, the miner will allow non-registered hotkeys to mine.",
        default=False,
    )

    # Adds subtensor specific arguments i.e. --subtensor.chain_endpoint ... --subtensor.network ...
    # TW-MIGRATE: TWM008 the kit's chain gateway and MetagraphCache, or bt.Subtensor directly
    bt.subtensor.add_args(parser)

    # Adds logging specific arguments i.e. --logging.debug ..., --logging.trace .. or --logging.logging_dir ...
    # TW-MIGRATE: TWM025 remove it: the kit configures logging (TW_LOG_LEVEL); use the standard logging module for anything else
    bt.logging.add_args(parser)

    # Adds wallet specific arguments i.e. --wallet.name ..., --wallet.hotkey ./. or --wallet.path ...
    # TW-MIGRATE: TWM014 load the hotkey only (TW_WALLET_*); the kit never touches the coldkey
    bt.wallet.add_args(parser)

    # Adds axon specific arguments i.e. --axon.port ...
    Axon.add_args(parser)

    # Activating the parser to read any command-line inputs.
    # To print help message, run python3 template/miner.py --help
    # TW-MIGRATE: TWM006 kit settings (TW_* variables, spec 12) or the team's own config
    config = bt.config(parser)

    # Logging captures events for diagnosis or understanding miner's behavior.
    config.full_path = os.path.expanduser(
        "{}/{}/{}/netuid{}/{}".format(
            config.logging.logging_dir,
            config.wallet.name,
            config.wallet.hotkey,
            config.netuid,
            "miner",
        )
    )
    # Ensure the directory for logging exists, else create one.
    if not os.path.exists(config.full_path):
        os.makedirs(config.full_path, exist_ok=True)
    return config
