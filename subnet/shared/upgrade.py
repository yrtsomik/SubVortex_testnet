import os
import re
import path
import codecs
import requests
import subprocess
import bittensor as bt

VERSION_URL = "https://github.com/eclipsevortex/SubVortex/blob/main/subnet/__init__.py"


def convert_version_to_number(version):
    return int(version.replace(".", "").replace("-", "").replace("_", ""))


def compare_versions(version1, version2):
    def version_tuple(version):
        return tuple(map(int, version.split(".")))

    v1 = version_tuple(version1)
    v2 = version_tuple(version2)

    if v1 < v2:
        return -1
    elif v1 > v2:
        return 1

    return 0


def get_remote_version():
    """
    Get the remote version of the subnet
    """
    response = requests.get(VERSION_URL)
    if response.status_code != 200:
        bt.logging.warning(
            f"Failed to get the remote version: {response.status_code} - {response.reason}"
        )

    lines = response.text.split("\n")
    for line in lines:
        if line.startswith("__version__"):
            version_info = line.split("=")[1].strip(" \"'").replace('"', "")
            return version_info


def get_local_version():
    """
    Get the local version of the subnet
    """
    try:
        # loading version from __init__.py
        here = os.path.abspath(os.path.dirname(__file__))
        with codecs.open(
            os.path.join(here, "../__init__.py"), encoding="utf-8"
        ) as init_file:
            content = init_file.read()
            version_match = re.search(
                r"^__version__ = ['\"]([^'\"]*)['\"]", content, re.M
            )
            version_string = version_match.group(1)
        return version_string
    except Exception as e:
        bt.logging.error(f"Error getting local version. : {e}")
        return ""


def check_version_updated():
    '''
    Check if the subnet need to upgrade or downgrade
    -1 - The local subnet must be upgraded
    0  - The local subnet has the same version than the remote one
    1  - The local subnet must be downgraded
    '''
    remote_version = convert_version_to_number(get_remote_version())
    local_version = convert_version_to_number(get_local_version())
    if local_version == remote_version:
        bt.logging.info(f"The subnet is up to date.")
        return 0

    if local_version < remote_version:
        bt.logging.info(f"The subnet must be upgraded")
        return -1

    bt.logging.info(f"The subnet must be downgraded")
    return 1


def check_for_new_release(repo_owner, repo_name):
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/releases/latest"
    response = requests.get(url)
    if response.status_code == 200:
        latest_version = response.json()["tag_name"]
        return latest_version
        # if latest_version != current_version:
    #         print(f"A new release ({latest_version}) is available.")
    #         return latest_version
    #     else:
    #         print("Your project is up-to-date.")
    # else:
    #     print("Failed to check for new releases.")


def try_update_repository():
    bt.logging.info("Try updating packages...")

    try:
        # Get the tag
        check_for_new_release()

        # Update dependencies
        # subprocess.run(["pip", "install", "-r", "requirements.txt", "--upgrade"])

        bt.logging.info("Updating packages finished.")

    except Exception as e:
        bt.logging.info(f"Updating packages failed {e}")


def try_upgrade():
    repo_owner = "eclipsevortex"
    repo_name = "SubVortex"

    # Get the current version
    current_version = f"v{get_local_version()}"

    # Get the latest version
    latest_version = check_for_new_release(repo_owner, repo_name)
    if latest_version is None:
        bt.logging.warning("Could not get the latest version.")
        return

    # Compare the versions
    result = compare_versions(current_version, latest_version)
    if result == 0:
        bt.logging.success("Latest version already installed.")
        return

    # Pull the latest version

    # Update dependencies
    subprocess.run(["pip", "install", "-r", "requirements.txt", "--upgrade"])


    bt.logging.success("Latest version installed succesfully.")


if __name__ == "__main__":
    try_upgrade()
