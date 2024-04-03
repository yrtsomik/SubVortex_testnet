import torch
import time
import asyncio
import bittensor as bt
from typing import List

from subnet import protocol
from subnet.constants import (
    AVAILABILITY_WEIGHT,
    LATENCY_WEIGHT,
    RELIABILLITY_WEIGHT,
    DISTRIBUTION_WEIGHT,
)
from subnet.shared.subtensor import get_current_block
from subnet.validator.miner import Miner
from subnet.validator.event import EventSchema
from subnet.validator.utils import ping_and_retry_uids
from subnet.validator.bonding import update_statistics
from subnet.validator.state import log_event
from subnet.validator.score import (
    check_multiple_miners_on_same_ip,
    compute_availability_score,
    compute_reliability_score,
    compute_latency_score,
    compute_distribution_score,
)
from substrateinterface.base import SubstrateInterface


CHALLENGE_NAME = "Challenge"
DEFAULT_PROCESS_TIME = 5


async def handle_synapse(self, uid: int):
    # Get the miner
    miner: Miner = next((miner for miner in self.miners if miner.uid == uid), None)

    verified = False
    process_time: float = DEFAULT_PROCESS_TIME
    try:
        # Create a subtensor with the ip return by the synapse
        substrate = SubstrateInterface(
            ss58_format=bt.__ss58_format__,
            use_remote_preset=True,
            url=f"ws://{miner.ip}:9944",
            type_registry=bt.__type_registry__,
        )

        # Start the timer
        start_time = time.time()

        # Get the current block from the miner subtensor
        miner_block = substrate.get_block()
        if miner_block != None:
            miner_block = miner_block["header"]["number"]

        # Compute the process time
        process_time = time.time() - start_time

        # Get the current block from the validator subtensor
        validator_block = get_current_block(self.subtensor)

        # Check both blocks are the same
        verified = miner_block == validator_block or miner_block is not None

        bt.logging.trace(
            f"[{CHALLENGE_NAME}][{uid}] Verified ? {verified} - val: {validator_block}, miner:{miner_block}"
        )
    except Exception:
        verified = False
        bt.logging.warning(f"[{CHALLENGE_NAME}][{uid}] Verified ? False")

    # Update the miner object
    finally:
        miner.verified = False
        miner.process_time = process_time


async def challenge_data(self):
    start_time = time.time()
    bt.logging.debug(f"[{CHALLENGE_NAME}] Step starting")

    event = EventSchema(
        successful=[],
        completion_times=[],
        availability_scores=[],
        latency_scores=[],
        reliability_scores=[],
        distribution_scores=[],
        moving_averaged_scores=[],
        countries=[],
        block=self.subtensor.get_current_block(),
        uids=[],
        step_length=0.0,
        best_uid=-1,
        best_hotkey="",
        rewards=[],
    )

    # Select the miners
    uids, _ = await ping_and_retry_uids(self, k=10)
    bt.logging.debug(f"[{CHALLENGE_NAME}] Available uids {uids}")

    # Initialise the rewards object
    rewards: torch.FloatTensor = torch.zeros(len(uids), dtype=torch.float32).to(
        self.device
    )

    # Execute the challenges
    tasks = []
    for idx, (uid) in enumerate(uids):
        tasks.append(asyncio.create_task(handle_synapse(self, uid)))
        await asyncio.gather(*tasks)

    # Init wandb table data
    availability_scores = []
    latency_scores = []
    reliability_scores = []
    distribution_scores = []

    # Compute the score
    for idx, (uid) in enumerate(uids):
        # Get the miner
        miner: Miner = next((miner for miner in self.miners if miner.uid == uid), None)

        # Initialise scores
        availability_score = 0
        latency_score = 0
        reliability_score = 0
        distribution_score = 0

        # Check there is only one miner per ip
        number_of_miners = check_multiple_miners_on_same_ip(miner, self.miners)

        # Compute score for availability
        availability_score = compute_availability_score(miner)
        availability_scores.append(availability_score)
        bt.logging.debug(
            f"[{CHALLENGE_NAME}][{uid}] Availability score {availability_score}"
        )

        # Compute score for latency
        latency_score = compute_latency_score(self.country, miner, self.miners)
        latency_scores.append(latency_score)
        bt.logging.debug(f"[{CHALLENGE_NAME}][{uid}] Latency score {latency_score}")

        # Compute score for reliability
        reliability_score = await compute_reliability_score(miner)
        reliability_scores.append(reliability_score)
        bt.logging.debug(
            f"[{CHALLENGE_NAME}][{uid}] Reliability score {reliability_score}"
        )

        # Compute score for distribution
        distribution_score = compute_distribution_score(miner, self.miners)
        distribution_scores.append((uid, distribution_score))
        bt.logging.debug(
            f"[{CHALLENGE_NAME}][{uid}] Distribution score {distribution_score}"
        )

        # Compute final score
        miner.score = rewards[idx] = (
            (AVAILABILITY_WEIGHT * availability_score)
            + (LATENCY_WEIGHT * latency_score)
            + (RELIABILLITY_WEIGHT * reliability_score)
            + (DISTRIBUTION_WEIGHT * distribution_score)
        ) / (
            AVAILABILITY_WEIGHT
            + LATENCY_WEIGHT
            + RELIABILLITY_WEIGHT
            + DISTRIBUTION_WEIGHT
        )

        bt.logging.info(f"[{CHALLENGE_NAME}][{uid}] Final score {rewards[idx]}")

        # Log the event data for this specific challenge
        event.uids.append(uid)
        event.countries.append(miner.country)
        event.successful.append(miner.verified)
        event.completion_times.append(miner.process_time)
        event.rewards.append(rewards[idx].item())
        event.availability_scores.append(availability_score)
        event.latency_scores.append(latency_score)
        event.reliability_scores.append(reliability_score)
        event.distribution_scores.append(distribution_score)

        # Send the score details to the miner
        response: List[protocol.Score] = await self.dendrite(
            axons=[self.metagraph.axons[uid]],
            synapse=protocol.Score(
                validator_uid=self.uid,
                count=number_of_miners,
                availability=availability_score,
                latency=latency_score,
                reliability=reliability_score,
                distribution=distribution_score,
                score=rewards[idx],
            ),
            deserialize=True,
            timeout=DEFAULT_PROCESS_TIME,
        )

        # Update the miner version
        version = next((version for version in response if version is not None), None)
        if version is not None:
            miner.version = version

        # Save miner snapshot in database
        await update_statistics(self, miner)

    # Compute forward pass rewards
    scattered_rewards: torch.FloatTensor = (
        self.moving_averaged_scores.to(self.device)
        .scatter(
            0,
            torch.tensor(uids).to(self.device),
            rewards.to(self.device),
        )
        .to(self.device)
    )
    bt.logging.trace(f"[{CHALLENGE_NAME}] Scattered rewards: {scattered_rewards}")

    # Update moving_averaged_scores with rewards produced by this step.
    # alpha of 0.2 means that each new score replaces 20% of the weight of the previous weights
    alpha: float = 0.2
    self.moving_averaged_scores = alpha * scattered_rewards + (
        1 - alpha
    ) * self.moving_averaged_scores.to(self.device)
    event.moving_averaged_scores = self.moving_averaged_scores.tolist()
    bt.logging.trace(
        f"[{CHALLENGE_NAME}] Updated moving avg scores: {self.moving_averaged_scores}"
    )

    # Display step time
    forward_time = time.time() - start_time
    event.step_length = forward_time
    bt.logging.debug(f"[{CHALLENGE_NAME}] Step finished in {forward_time:.2f}s")

    # Determine the best UID based on rewards
    if event.rewards:
        best_index = max(range(len(event.rewards)), key=event.rewards.__getitem__)
        event.best_uid = event.uids[best_index]
        event.best_hotkey = self.metagraph.hotkeys[event.best_uid]

    # Log event
    log_event(self, event)
