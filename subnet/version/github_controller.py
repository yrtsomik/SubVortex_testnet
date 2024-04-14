import requests
import subprocess
import bittensor as bt


class Github:
    def __init__(self, repo_owner="eclipsevortex", repo_name="SubVortex"):
        self.repo_owner = repo_owner
        self.repo_name = repo_name

    def get_version(self):
        """
        Get the latest release on github
        """
        url = f"https://api.github.com/repos/{self.repo_owner}/{self.repo_name}/releases/latest"
        response = requests.get(url)
        if response.status_code != 200:
            return None

        latest_version = response.json()["tag_name"]
        return latest_version[1:]

    def get_branch(self, tag="latest"):
        """
        Get the expected branch
        """
        if tag == "latest":
            subprocess.run(["git", "checkout", "main"], check=True)
            bt.logging.info(f"Successfully pulled source code for main branch'.")
        else:
            subprocess.run(["git", "checkout", f"tags/{tag}"], check=True)
            bt.logging.info(f"Successfully pulled source code for tag '{tag}'.")
