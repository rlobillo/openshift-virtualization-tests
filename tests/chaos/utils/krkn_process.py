import logging
import os
import subprocess
import sys

import yaml
from ocp_utilities.data_collector import write_to_file
from pytest_testconfig import config as py_config

from tests.chaos.constants import (
    CHAOS_ENGINE_FILE_PATH,
    KRKN_BASE_CONFIG_PATH,
    KRKN_CONFIG_PATH,
    KUBECONFIG_PATH,
)


LOGGER = logging.getLogger(__name__)


class KrknProcess:
    def __init__(self, repo_path):
        self.repo_path = repo_path
        self.base_config_path = KRKN_BASE_CONFIG_PATH
        self.config_path = KRKN_CONFIG_PATH
        self.process = None

    def run(self):
        """
        Runs the krkn process after creating a krkn config file.
        """
        if not os.path.exists(self.config_path):
            self._create_config_file()

        self.process = subprocess.Popen(
            args=[
                sys.executable,
                os.path.join(self.repo_path, "run_kraken.py"),
                "--config",
                self.config_path,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def wait(self):
        """
        Waits for the krkn process to finish.

        Returns:
            bool: True if the process ran without errors.
        """

        result = self.process.wait()

        if result != 0:
            self._get_logs()

        return result == 0

    def _create_config_file(self):
        """
        Creates a krkn config file based on krkn_base_config.yaml.
        """
        with open(self.base_config_path, "r") as file:
            cfg = yaml.safe_load(file)

        cfg["kraken"]["kubeconfig_path"] = KUBECONFIG_PATH
        cfg["kraken"]["chaos_scenarios"][0]["litmus_scenarios"][0][
            0
        ] = CHAOS_ENGINE_FILE_PATH

        with open(self.config_path, "w") as file:
            yaml.dump(cfg, file)

    def _get_logs(self):
        """
        Gets the lasts 20 lines of the stdout of the krkn process.
        """
        stdout, stderr = (item.decode("utf-8") for item in self.process.communicate())

        for line in stderr.splitlines()[-20:]:
            LOGGER.info(line)

        write_to_file(
            file_name="krkn_process_logs.txt",
            content=stderr,
            extra_dir_name="krkn",
            base_directory=py_config["data_collector"]["data_collector_base_directory"],
        )
