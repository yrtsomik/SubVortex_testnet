import os
import re
import codecs
import bittensor as bt
from os import path

from subnet.version.github_controller import Github
from subnet.version.interpreter_controller import Interpreter
from subnet.version.redis_controller import Redis

here = path.abspath(path.dirname(__file__))


class VersionControl:
    def __init__(self):
        self.github = Github()
        self.interpreter = Interpreter()
        self.redis = Redis()

    def get_version(self):
        with codecs.open(
            os.path.join(here, "../__init__.py"), encoding="utf-8"
        ) as init_file:
            version_match = re.search(
                r"^__version__ = ['\"]([^'\"]*)['\"]", init_file.read(), re.M
            )
            version_string = version_match.group(1)
            return version_string

    def upgrade_subnet(self):
        try:
            # Get the local version
            current_version = self.get_version()
            bt.logging.info(f"[Subnet] Current version: {current_version}")

            # Get the remote version
            remote_version = self.github.get_version()
            bt.logging.info(f"[Subnet] Remote version: {remote_version}")

            # Check if the subnet has to be upgraded
            if current_version == remote_version:
                bt.logging.success("[Subnet] Already up to date")
                return

            bt.logging.info("[Subnet] Upgrading...")

            # Pull the branch
            self.github.get_branch()

            # Install dependencies
            self.interpreter.upgrade_dependencies()

            bt.logging.success("Subnet upgraded successfully")
        except Exception as err:
            bt.logging.error(f"Failed to upgrade the subnet: {err}")

    def upgrade_redis(self):
        try:
            # Get the local version
            current_version = self.redis.get_version()
            bt.logging.info(f"[Redis] Current version: {current_version}")

            # Get latest version
            latest_version = self.redis.get_latest_version()
            bt.logging.info(f"[Redis] Latest version: {latest_version}")

            # Check if the subnet has to be upgraded
            if current_version == latest_version:
                bt.logging.success("[Redis] Already up to date")
                return


        except Exception as err:
            bt.logging.error(f"Failed to upgrade redis: {err}")

    def upgrade_subtensor(self):
        try:
            pass
        except Exception as err:
            bt.logging.error(f"Failed to upgrade subtensor: {err}")

    def upgrade(self):
        try:
            # Upgrade subnet
            self.upgrade_subnet()

            # Upgrade redis
            self.upgrade_redis()

            # Upgrade subtensor
            self.upgrade_subtensor()
        except Exception as err:
            bt.logging.error(f"Upgrade failed: {err}")


if __name__ == "__main__":
    VersionControl().upgrade()
