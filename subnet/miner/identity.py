import sys
import argparse
import bittensor as bt

from subnet.shared.checks import check_registration
from subnet.shared.subtensor import publish_metadata, retrieve_metadata


def register(config):
    # The axon handles request processing, allowing validators to send this process requests.
    axon_ip = bt.net.get_external_ip()

    # Init subtensor
    bt.logging.debug("loading subtensor")
    subtensor = bt.subtensor(config=config, network="local")
    bt.logging.debug(str(subtensor))

    # Init wallet.
    bt.logging.debug("loading wallet")
    wallet = bt.wallet(config=config)
    wallet.create_if_non_existent()
    check_registration(subtensor, wallet, config.netuid)
    bt.logging.debug(f"wallet: {str(wallet)}")

    # Init metagraph.
    bt.logging.debug("loading metagraph")
    metagraph = bt.metagraph(
        netuid=config.netuid, network=subtensor.network, sync=False
    )  # Make sure not to sync without passing subtensor
    metagraph.sync(subtensor=subtensor)  # Sync metagraph with subtensor.
    bt.logging.debug(str(metagraph))

    # Check if there is already a miner using the same ip
    bt.logging.debug("Checking potential redundant ip")
    number_of_miners = len(
        [
            axon
            for axon in metagraph.axons
            if axon_ip == axon.ip and axon.hotkey != wallet.hotkey.ss58_address
        ]
    )
    if number_of_miners > 0:
        bt.logging.error(
            f"At least one other miner is using the ip {axon_ip}. Please move your extra miner(s) if you have more than one or change your VPS as it maybe compromised."
        )
        sys.exit(1)

    # Commit the ip on the blockchain to allow validator to check my identity
    bt.logging.info(f"Registering ip {axon_ip} into the chain")
    ip, _ = retrieve_metadata(subtensor, config.netuid, wallet.hotkey.ss58_address)
    if ip != axon_ip:
        publish_metadata(subtensor, wallet, config.netuid, axon_ip)
        bt.logging.info(f"Ip {axon_ip} registered")
    else:
        bt.logging.info(f"Ip {axon_ip} already registered")


def check(config):
    # The axon handles request processing, allowing validators to send this process requests.
    axon_ip = bt.net.get_external_ip()

    # Init subtensor
    bt.logging.debug("loading subtensor")
    subtensor = bt.subtensor(config=config, network="local")
    bt.logging.debug(str(subtensor))

    # Init wallet.
    bt.logging.debug("loading wallet")
    wallet = bt.wallet(config=config)
    wallet.create_if_non_existent()
    check_registration(subtensor, wallet, config.netuid)
    bt.logging.debug(f"wallet: {str(wallet)}")

    # Init metagraph.
    bt.logging.debug("loading metagraph")
    metagraph = bt.metagraph(
        netuid=config.netuid, network=subtensor.network, sync=False
    )  # Make sure not to sync without passing subtensor
    metagraph.sync(subtensor=subtensor)  # Sync metagraph with subtensor.
    bt.logging.debug(str(metagraph))

    # Check if there is already a miner using the same ip
    bt.logging.debug("Checking potential redundant ip")
    number_of_miners = len(
        [
            axon
            for axon in metagraph.axons
            if axon_ip == axon.ip and axon.hotkey != wallet.hotkey.ss58_address
        ]
    )
    if number_of_miners > 0:
        bt.logging.error(
            f"At least one other miner is using the ip {axon_ip}. Please move your extra miner(s) if you have more than one or change your VPS as it maybe compromised."
        )
        sys.exit(1)

    # Commit the ip on the blockchain to allow validator to check my identity
    ip, _ = retrieve_metadata(subtensor, config.netuid, wallet.hotkey.ss58_address)
    bt.logging.info(
        f"The ip registered on the blockchain is {ip}. If it is not your ip, please run the registration with the right one."
    )


def main(config):
    if config.action == "check":
        check(config)
    elif config.action == "register":
        register(config)


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser()
        bt.subtensor.add_args(parser)
        bt.logging.add_args(parser)
        bt.wallet.add_args(parser)
        parser.add_argument(
            "--netuid", type=int, help="Storage network netuid", default=7
        )
        parser.add_argument(
            "--action",
            type=str,
            help="Type action to execute, can be check or register. Default is check",
            default="check",
        )
        config = bt.config(parser)
        bt.logging(config=config)

        main(config)
    except KeyboardInterrupt:
        print("KeyboardInterrupt")
    except Exception as e:
        print(f"Registration failed: {e}")
