import bittensor as bt
from redis import asyncio as aioredis

CURRENT_VERSION = "2.1.0"
PREVIOUS_VERSION = "2.0.0"

NEW_STATS_FIELDS = [
    ("uid", -1),
    ("version", "0.0.0"),
    ("country", ""),
    ("verified", 0),
    ("score", 0),
    ("availability_score", 0),
    ("latency_score", 0),
    ("reliability_score", 0),
    ("distribution_score", 0),
    ("challenge_successes", 0),
    ("challenge_attempts", 0),
    ("process_time", 0),
]

REMOVE_STATS_FIELDS = [
    "subtensor_successes",
    "subtensor_attempts",
    "metric_successes",
    "metric_attempts",
    "total_successes",
    "tier",
]


async def rollout(database: aioredis.StrictRedis):
    # async for key in database.scan_iter("*"):
    #     metadata_dict = await database.hgetall(key)

    #     for key in REMOVE_STATS_FIELDS:
    #         if f"b{key}" in metadata_dict:
    #             await database.hdel(key, f"b{key}")

    #     for (key, value) in NEW_STATS_FIELDS:
    #         if f"b{key}" not in metadata_dict:
    #             await database.hset(key, f"b{key}", value)
    bt.logging.success(f"Upgraded to v{CURRENT_VERSION} succesfully")


async def rollback(database: aioredis.StrictRedis):
    # async for key in database.scan_iter("*"):
    #     metadata_dict = await database.hgetall(key)

    #     for (key, _) in NEW_STATS_FIELDS:
    #         if f"b{key}" not in metadata_dict:
    #             await database.hdel(key, f"b{key}")
    bt.logging.success(f"Downgraded to v{CURRENT_VERSION} succesfully")
