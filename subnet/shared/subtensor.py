import time
import bittensor as bt

from math import floor
from functools import lru_cache, update_wrapper
from typing import Callable, Any
from bittensor.extrinsics.serving import get_metadata, MetadataError


def _ttl_hash_gen(seconds: int):
    start_time = time.time()
    while 1:
        yield floor((time.time() - start_time) / seconds)


# LRU Cache with TTL
def ttl_cache(maxsize: int = 128, typed: bool = False, ttl: int = -1):
    if ttl <= 0:
        ttl = 65536
    hash_gen = _ttl_hash_gen(ttl)

    def wrapper(func: Callable) -> Callable:
        @lru_cache(maxsize, typed)
        def ttl_func(ttl_hash, *args, **kwargs):
            return func(*args, **kwargs)

        def wrapped(*args, **kwargs) -> Any:
            th = next(hash_gen)
            return ttl_func(th, *args, **kwargs)

        return update_wrapper(wrapped, func)

    return wrapper


# 12 seconds updating block.
@ttl_cache(maxsize=1, ttl=12)
def get_current_block(subtensor) -> int:
    return subtensor.get_current_block()


def retrieve_metadata(subtensor: bt.subtensor, netuid: int, hotkey: str):
    metadata = get_metadata(subtensor, netuid, hotkey)
    if not metadata:
        return None, None

    commitment = metadata["info"]["fields"][0]
    hex_data = commitment[list(commitment.keys())[0]][2:]
    return bytes.fromhex(hex_data).decode()


def publish_metadata(
    subtensor: bt.subtensor,
    wallet: bt.wallet,
    netuid: int,
    ip: str,
    retry_delay_secs: int = 60,
):
    # We can only commit to the chain every 20 minutes, so run this in a loop, until
    # successful.
    while True:
        try:
            subtensor.commit(wallet, netuid, ip)

            bt.logging.info(
                "Wrote metadata to the chain. Checking we can read it back..."
            )

            ip = retrieve_metadata(subtensor, wallet.hotkey.ss58_address)

            if not ip or ip != ip:
                bt.logging.error(
                    f"Failed to read back metadata from the chain. Expected: {ip}, got: {ip}"
                )
                raise ValueError(
                    f"Failed to read back metadata from the chain. Expected: {ip}, got: {ip}"
                )

            bt.logging.success("Committed metadata to the chain.")
            break
        except (MetadataError, Exception) as e:
            bt.logging.error(f"Failed to send metadata on the chain: {e}")
            bt.logging.error(f"Retrying in {retry_delay_secs} seconds...")
            time.sleep(retry_delay_secs)
