import logging
import os

import yaml
from ocp_resources.machine_config_pool import MachineConfigPool
from ocp_resources.node import Node
from ocp_utilities.data_collector import (
    collect_pods_data,
    collect_resources_yaml_instance,
    prepare_pytest_item_data_dir,
)
from pytest_testconfig import config as py_config

import utilities.infra
from utilities.constants import MACHINE_CONFIG_PODS_TO_COLLECT


LOGGER = logging.getLogger(__name__)


def collect_mcp_information():
    data_collector_dict = get_data_collector_dict()
    base_directory = data_collector_dict["data_collector_base_directory"]
    LOGGER.warning("Collecting MachineConfigPool data for triage.")
    collect_resources_yaml_instance(
        resources_to_collect=[MachineConfigPool, Node], base_directory=base_directory
    )

    pods_to_collect = []
    for pod_prefix in MACHINE_CONFIG_PODS_TO_COLLECT:
        pods_to_collect.extend(
            utilities.infra.get_pod_by_name_prefix(
                dyn_client=utilities.infra.get_admin_client(),
                pod_prefix=pod_prefix,
                namespace="openshift-machine-config-operator",
                get_all=True,
            )
        )
    collect_pods_data(pods_list=pods_to_collect, base_directory=base_directory)


def get_data_collector_dict():
    collector_dict = py_config.get("data_collector")
    if collector_dict:
        return collector_dict
    return py_config["local_data_collector"]


def set_data_collector_values(session):
    data_collector = session.config.getoption("--data-collector")
    if data_collector:
        with open(data_collector, "r") as fd:
            py_config["data_collector"] = yaml.safe_load(fd.read())
        return py_config["data_collector"]

    else:
        py_config["local_data_collector"] = {
            "data_collector_base_directory": (
                f"{'/data/' if os.environ.get('CNV_TESTS_CONTAINER') else ''}tests-collected-info"
            )
        }
        return py_config["local_data_collector"]


def set_collector_directory(item, subdirectory_name):
    data_collector_dict = get_data_collector_dict()
    base_directory = data_collector_dict["data_collector_base_directory"]
    data_collector_dict["collector_directory"] = prepare_pytest_item_data_dir(
        item=item, base_directory=base_directory, subdirectory_name=subdirectory_name
    )
