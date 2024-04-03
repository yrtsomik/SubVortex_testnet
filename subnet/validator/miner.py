from typing import List

from subnet.validator.utils import get_available_uids
from subnet.validator.localisation import get_country


class Miner:
    index: int = -1
    uid: int = -1
    hotkey: str = None
    ip: str = "0.0.0.0",
    version: str = "0.0.0"
    country: str = None
    verified: bool = False
    score: float = 0
    availability_score: float = 0
    reliability_score: float = 0
    latency_score: float = 0
    distribution_score: float = 0
    challenge_successes: int = 0
    challenge_attempts: int = 0
    process_time: float = 0

    def __init__(
        self,
        index,
        uid,
        hotkey,
        ip,
        version,
        country,
        verified,
        score,
        availability_score,
        latency_score,
        reliability_score,
        distribution_score,
        challenge_successes,
        challenge_attempts,
        process_time,
    ):
        self.index = index
        self.uid = int(uid or -1)
        self.hotkey = hotkey
        self.ip = ip or "0.0.0.0",
        self.version = version or "0.0.0"
        self.country = country or ""
        self.verified = bool(verified or False)
        self.score = float(score or 0)
        self.availability_score = float(availability_score or 0)
        self.reliability_score = float(reliability_score or 0)
        self.latency_score = float(latency_score or 0)
        self.distribution_score = float(distribution_score or 0)
        self.challenge_successes = int(challenge_successes or 0)
        self.challenge_attempts = int(challenge_attempts or 0)
        self.process_time = float(process_time or 0)

    def reset(self, hotkey: str, ip: str):
        self.hotkey = hotkey
        self.ip = ip or "0.0.0.0"
        self.country = ""
        self.verified = False
        self.score = 0
        self.availability_score = 0
        self.reliability_score = 0
        self.latency_score = 0
        self.distribution_score = 0
        self.challenge_successes = 0
        self.challenge_attempts = 0
        self.process_time =  0
        pass

    @property
    def snapshot(self):
        # index and ip are not stored in redis database
        # index because we do not need 
        # ip/hotkey because we do not to keep a track of them
        return {
            "uid": self.uid,
            "version": self.version,
            "country": self.country,
            "verified": int(self.verified),
            "score": self.score,
            "availability_score": self.availability_score,
            "latency_score": self.latency_score,
            "reliability_score": self.reliability_score,
            "distribution_score": self.distribution_score,
            "challenge_successes": self.challenge_successes,
            "challenge_attempts": self.challenge_attempts,
            "process_time": self.process_time,
        }

    def __str__(self):
        return f"Miner(index={self.index}, uid={self.uid}, hotkey={self.hotkey}, ip={self.ip}, version={self.version}, country={self.country}, verified={self.verified}, score={self.score}, availability_score={self.availability_score}, latency_score={self.latency_score}, reliability_score={self.reliability_score}, distribution_score={self.distribution_score}, challenge_attempts={self.challenge_attempts}, challenge_successes={self.challenge_successes}, process_time={self.process_time})"

    def __repr__(self):
        return f"Miner(index={self.index}, uid={self.uid}, hotkey={self.hotkey}, ip={self.ip}, version={self.version}, country={self.country}, verified={self.verified}, score={self.score}, availability_score={self.availability_score}, latency_score={self.latency_score}, reliability_score={self.reliability_score}, distribution_score={self.distribution_score}, challenge_attempts={self.challenge_attempts}, challenge_successes={self.challenge_successes}, process_time={self.process_time})"


def get_field_value(value, default_value=None):
    field_value = value.decode("utf-8") if isinstance(value, bytes) else value
    return field_value or default_value


async def get_miners(self) -> List[Miner]:
    """
    Load the miners stored in the database
    """
    miners: List[Miner] = []

    uids = get_available_uids(self)
    for idx, (uid) in enumerate(uids):
        axon = self.metagraph.axons[uid]

        statistics = await self.database.hgetall(f"stats:{axon.hotkey}")

        version = get_field_value(statistics.get(b"version"), "0.0.0")
        country = get_field_value(statistics.get(b"country")) or get_country(axon.ip)
        verified = get_field_value(statistics.get(b"verified"), 0)
        score = get_field_value(statistics.get(b"score"), 0)
        availability_score = get_field_value(statistics.get(b"availability_score"), 0)
        latency_score = get_field_value(statistics.get(b"latency_score"), 0)
        reliability_score = get_field_value(statistics.get(b"reliability_score"), 0)
        distribution_score = get_field_value(statistics.get(b"distribution_score"), 0)
        challenge_successes = get_field_value(statistics.get(b"challenge_successes"), 0)
        challenge_attempts = get_field_value(statistics.get(b"challenge_attempts"), 0)
        process_time = get_field_value(statistics.get(b"process_time"), 0)

        miner = Miner(
            idx,
            uid,
            axon.ip,
            axon.hotkey,
            version,
            country,
            verified,
            score,
            availability_score,
            latency_score,
            reliability_score,
            distribution_score,
            challenge_successes,
            challenge_attempts,
            process_time,
        )

        miners.append(miner)

    return miners
