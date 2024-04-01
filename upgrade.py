# The MIT License (MIT)
# Copyright © 2024 Eclipse Vortex

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the “Software”), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial portions of
# the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
import os
import re
import path
import codecs
import requests
import bittensor as bt
from substrateinterface import SubstrateInterface


def get_local_version():
    """
    Get the local version of the subnet
    """
    try:
        # loading version from __init__.py
        here = os.path.abspath(os.path.dirname(__file__))
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


def check_for_new_release(repo_owner, repo_name, current_version):
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/releases/latest"
    response = requests.get(url)
    if response.status_code == 200:
        latest_version = response.json()["tag_name"]
        print(latest_version)
        print(current_version)
        if latest_version != current_version:
            print(f"A new release ({latest_version}) is available.")
            return latest_version
        else:
            print("Your project is up-to-date.")
    else:
        print("Failed to check for new releases.")


def main():
    bt.logging.info("Try updating packages...")

    try:
        # Get the current version
        current_version = get_local_version()

        # Get the tag
        check_for_new_release(current_version)

        # Update dependencies
        # subprocess.run(["pip", "install", "-r", "requirements.txt", "--upgrade"])

        bt.logging.info("Updating packages finished.")

    except Exception as e:
        bt.logging.info(f"Updating packages failed {e}")


if __name__ == "__main__":
    main()
