import bittensor as bt
from redis import asyncio as aioredis

CURRENT_VERSION = "0.2.4"
PREVIOUS_VERSION = ""

async def rollout(database: aioredis.StrictRedis):
    bt.logging.success(f"Upgraded to v{CURRENT_VERSION} succesfully")


async def rollback(database: aioredis.StrictRedis):
    bt.logging.success(f"Downgraded to v{PREVIOUS_VERSION} succesfully")

