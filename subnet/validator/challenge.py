import torch
import time
import asyncio
import bittensor as bt
from typing import List

from subnet import protocol
from subnet.shared.subtensor import get_current_block
from subnet.validator.miner import Miner
from subnet.validator.event import EventSchema
from subnet.validator.utils import get_next_uids, ping_uid
from subnet.validator.bonding import update_statistics
from subnet.validator.localisation import get_country
from subnet.validator.state import log_event
from subnet.validator.score import (
    compute_availability_score,
    compute_reliability_score,
    compute_latency_score,
    compute_distribution_score,
    compute_final_score,
)
from substrateinterface.base import SubstrateInterface


CHALLENGE_NAME = "Challenge"
DEFAULT_PROCESS_TIME = 5


async def handle_synapse(self, uid: int):
    # Get the miner
    miner: Miner = next((miner for miner in self.miners if miner.uid == uid), None)

    # Check the miner is available
    available = await ping_uid(self, miner.uid)
    if available == False:
        miner.verified = False
        miner.process_time = DEFAULT_PROCESS_TIME
        bt.logging.warning(f"[{CHALLENGE_NAME}][{miner.uid}] Miner is not reachable")
        return

    bt.logging.trace(f"[{CHALLENGE_NAME}][{miner.uid}] Miner verified")

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
            f"[{CHALLENGE_NAME}][{miner.uid}] Subtensor verified ? {verified} - val: {validator_block}, miner:{miner_block}"
        )
    except Exception as ex:
        verified = False
        bt.logging.warning(
            f"[{CHALLENGE_NAME}][{miner.uid}] Subtensor not verified: {ex}"
        )

    # Update the miner object
    finally:
        miner.verified = verified
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
    validator_hotkey = self.metagraph.hotkeys[self.uid]
    uids = await get_next_uids(self, validator_hotkey, k=10)
    bt.logging.debug(f"[{CHALLENGE_NAME}] Available uids {uids}")

    # Execute the challenges
    tasks = []
    for idx, (uid) in enumerate(uids):
        tasks.append(asyncio.create_task(handle_synapse(self, uid)))
        await asyncio.gather(*tasks)

    # Initialise the rewards object
    rewards: torch.FloatTensor = torch.zeros(len(uids), dtype=torch.float32).to(
        self.device
    )

    # Init wandb table data
    availability_scores = []
    latency_scores = []
    reliability_scores = []
    distribution_scores = []

    bt.logging.info(f"[{CHALLENGE_NAME}] Starting evaluation")

    # Compute the score
    for idx, (uid) in enumerate(uids):
        # Get the miner
        miner: Miner = next((miner for miner in self.miners if miner.uid == uid), None)
        bt.logging.info(f"[{CHALLENGE_NAME}][{miner.uid}] Computing score...")

        # Check the miner's ip is not used by multiple miners (1 miner = 1 ip)
        if miner.ip_occurences != 1:
            bt.logging.warning(
                f"[{CHALLENGE_NAME}][{miner.uid}] {miner.ip_occurences} miner(s) associated with the ip"
            )

        # Compute score for availability
        miner.availability_score = compute_availability_score(miner)
        availability_scores.append(miner.availability_score)
        bt.logging.debug(
            f"[{CHALLENGE_NAME}][{miner.uid}] Availability score {miner.availability_score}"
        )

        # Compute score for latency
        miner.latency_score = compute_latency_score(self.country, miner, self.miners)
        latency_scores.append(miner.latency_score)
        bt.logging.debug(
            f"[{CHALLENGE_NAME}][{miner.uid}] Latency score {miner.latency_score}"
        )

        # Compute score for reliability
        miner.reliability_score = await compute_reliability_score(miner)
        reliability_scores.append(miner.reliability_score)
        bt.logging.debug(
            f"[{CHALLENGE_NAME}][{miner.uid}] Reliability score {miner.reliability_score}"
        )

        # Compute score for distribution
        miner.distribution_score = compute_distribution_score(miner, self.miners)
        distribution_scores.append((miner.uid, miner.distribution_score))
        bt.logging.debug(
            f"[{CHALLENGE_NAME}][{miner.uid}] Distribution score {miner.distribution_score}"
        )

        # Compute final score
        miner.score = compute_final_score(miner)
        rewards[idx] = miner.score
        bt.logging.info(f"[{CHALLENGE_NAME}][{miner.uid}] Final score {miner.score}")

        # Log the event data for this specific challenge
        event.uids.append(miner.uid)
        event.countries.append(miner.country)
        event.successful.append(miner.verified)
        event.completion_times.append(miner.process_time)
        event.rewards.append(miner.score)
        event.availability_scores.append(miner.availability_score)
        event.latency_scores.append(miner.latency_score)
        event.reliability_scores.append(miner.reliability_score)
        event.distribution_scores.append(miner.distribution_score)

        # Send the score details to the miner
        response: List[protocol.Score] = await self.dendrite(
            axons=[self.metagraph.axons[miner.uid]],
            synapse=protocol.Score(
                validator_uid=self.uid,
                count=miner.ip_occurences,
                availability=miner.availability_score,
                latency=miner.latency_score,
                reliability=miner.reliability_score,
                distribution=miner.distribution_score,
                score=miner.score,
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

    bt.logging.trace(f"[{CHALLENGE_NAME}] Rewards: {rewards}")

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
