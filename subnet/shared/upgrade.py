import os
import re
import path
import codecs
import requests
import bittensor as bt

VERSION_URL = "https://github.com/eclipsevortex/SubVortex/blob/main/subnet/__init__.py"


def convert_version_to_number(version):
    return int(version.replace(".", "").replace("-", "").replace("_", ""))


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
        here = path.abspath(path.dirname(__file__))
        with codecs.open(
            os.path.join(here, "__init__.py"), encoding="utf-8"
        ) as init_file:
            version_match = re.search(
                r"^__version__ = ['\"]([^'\"]*)['\"]", init_file.read(), re.M
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


def try_update_repository():
    bt.logging.info("Try updating packages...")

    try:
        repo = git.Repo(search_parent_directories=True)
        repo_path = repo.working_tree_dir
        
        requirements_path = os.path.join(repo_path, "requirements.txt")
        
        python_executable = sys.executable
        subprocess.check_call([python_executable], "-m", "pip", "install", "-r", requirements_path)
        bt.logging.info("Updating packages finished.")
        
    except Exception as e:
        bt.logging.info(f"Updating packages failed {e}")


def try_upgrade():
    result = check_version_updated()
    if result == 0:
        return
    
    # Pull the repository
    try_upgrade_repository()
