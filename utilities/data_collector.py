import logging

from ocp_resources.machine_config_pool import MachineConfigPool
from ocp_resources.node import Node
from ocp_utilities.data_collector import (
    collect_pods_data,
    collect_resources_yaml_instance,
)
from pytest_testconfig import config as py_config

import utilities.infra
from utilities.constants import MACHINE_CONFIG_PODS_TO_COLLECT


LOGGER = logging.getLogger(__name__)


def collect_mcp_information():
    base_directory = py_config["data_collector"]["data_collector_base_directory"]
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
            )
        )
    collect_pods_data(pods_list=pods_to_collect, base_directory=base_directory)
