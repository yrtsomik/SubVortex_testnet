import bittensor as bt
from redis import asyncio as aioredis

CURRENT_VERSION = "2.0.0"
PREVIOUS_VERSION = "0.2.4"

async def rollout(database: aioredis.StrictRedis):
    bt.logging.success(f"Upgraded to v{CURRENT_VERSION} succesfully")


async def rollback(database: aioredis.StrictRedis):
    bt.logging.success(f"Downgraded to v{PREVIOUS_VERSION} succesfully")

