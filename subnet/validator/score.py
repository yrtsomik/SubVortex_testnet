import numpy as np
import bittensor as bt
from typing import List

from subnet.validator.miner import Miner
from subnet.validator.bonding import wilson_score_interval
from subnet.validator.localisation import (
    compute_localisation_distance,
    get_localisation,
)
from subnet.constants import (
    AVAILABILITY_FAILURE_REWARD,
    LATENCY_FAILURE_REWARD,
    DISTRIBUTION_FAILURE_REWARD,
)

# Controls how quickly the tolerance decreases with distance.
SIGMA = 20
# Longest distance between any two places on Earth is 20,010 kilometers
MAX_DISTANCE = 20010


def check_multiple_miners_on_same_ip(miner: Miner, miners: List[Miner]):
    """
    Check if there is more than one miner per ip
    """
    count = sum(1 for item in miners if item.ip == miner.ip)
    miner.verified = count == 1

    bt.logging.trace(
        f"[{miner.uid}][Score][Multiple Ip] {count} miner(s) associated with the ip"
    )

    return count


def compute_availability_score(miner: Miner):
    """
    Compute the availability score of the uid
    """

    miner.score = 1.0 if miner.verified else AVAILABILITY_FAILURE_REWARD
    return miner.score


async def compute_reliability_score(miner: Miner):
    """
    Compute the reliaiblity score of the uid based on the the ratio challenge_successes/challenge_attempts
    """
    # Step 1: Retrieve statistics
    miner.challenge_successes = miner.challenge_successes + int(miner.verified)
    miner.challenge_attempts = miner.challenge_attempts + 1
    bt.logging.trace(
        f"[{miner.uid}][Score][Reliability] # challenge attempts {miner.challenge_attempts}"
    )
    bt.logging.trace(
        f"[{miner.uid}][Score][Reliability] # challenge succeeded {miner.challenge_successes}"
    )

    # Step 2: Normalization
    miner.reliability_score = wilson_score_interval(
        miner.challenge_successes, miner.challenge_attempts
    )

    return miner.reliability_score


def compute_latency_score(validator_country, miner: Miner, miners: List[Miner]):
    """
    Compute the latency score of the uid based on the process time of all uids
    """
    if miner.verified == False:
        return LATENCY_FAILURE_REWARD
    
    bt.logging.trace(
        f"[{miner.uid}][Score][Latency] Process time {miner.process_time}"
    )

    # Step 1: Get the localisation of the validator
    validator_localisation = get_localisation(validator_country)

    # Step 2: Compute the miners process times by adding a tolerance
    miner_index = -1
    process_times = []
    for item in miners:
        if item.verified == False:
            # Exclude miners not verifed to not alterate the computation
            continue

        distance = 0
        location = get_localisation(item.country)
        if location is not None:
            distance = compute_localisation_distance(
                validator_localisation["latitude"],
                validator_localisation["longitude"],
                location["latitude"],
                location["longitude"],
            )

        scaled_distance = distance / MAX_DISTANCE
        tolerance = 1 - scaled_distance

        process_time = item.process_time * tolerance
        process_times.append(process_time)

        if miner_index == -1:
            miner_index = len(process_times) - 1
    bt.logging.trace(
        f"[{miner.uid}][Score][Latency] Process times with tolerange {process_times}"
    )

    # Step 3: Baseline Latency Calculation
    baseline_latency = np.mean(process_times)
    bt.logging.trace(f"[{miner.uid}][Score][Latency] Base latency {baseline_latency}")

    # Step 4: Relative Latency Score Calculation
    relative_latency_scores = []
    for process_time in process_times:
        relative_latency_score = 1 - (process_time / baseline_latency)
        relative_latency_scores.append(relative_latency_score)
    bt.logging.trace(
        f"[{miner.uid}][Score][Latency] Relative scores {relative_latency_scores}"
    )

    # Step 5: Normalization
    min_score = min(relative_latency_scores)
    bt.logging.trace(
        f"[{miner.uid}][Score][Latency] Minimum relative score {min_score}"
    )
    max_score = max(relative_latency_scores)
    bt.logging.trace(
        f"[{miner.uid}][Score][Latency] Maximum relative score {max_score}"
    )
    score = relative_latency_scores[miner_index]
    bt.logging.trace(f"[{miner.uid}][Score][Latency] Relative score {score}")

    miner.latency_score = (score - min_score) / (max_score - min_score)

    return miner.latency_score


def compute_distribution_score(miner: Miner, miners: List[Miner]):
    """
    Compute the distribution score of the uid based on the country of all uids
    """
    if miner.verified == False:
        return DISTRIBUTION_FAILURE_REWARD

    # Step 1: Country of the requested response
    country = miner.country

    # Step 1: Country the number of miners in the country
    count = 0
    for miner in miners:
        if miner.country == country:
            count = count + 1
    bt.logging.trace(f"[{miner.uid}][Score][Distribution] {count} uids in {country}")

    # Step 2: Compute the score
    miner.distribution_score = 1 / count if count > 0 else 0

    return miner.distribution_score
