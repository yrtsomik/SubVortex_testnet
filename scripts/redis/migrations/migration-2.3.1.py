import bittensor as bt

current = "2.3.1"
previous = "2.3.0"


async def rollout(args):
    bt.logging.info(f"Rollout release {current} successfully")


async def rollback(args):
    bt.logging.info(f"Rollback release {previous} successfully")
