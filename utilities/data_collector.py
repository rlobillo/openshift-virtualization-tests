import json
import logging
import os

import yaml
from ocp_resources.hyperconverged import HyperConverged
from ocp_resources.kubevirt import KubeVirt
from ocp_resources.machine_config_pool import MachineConfigPool
from ocp_resources.node import Node
from ocp_resources.pod import Pod
from ocp_utilities.infra import cluster_resource, get_client
from ocp_wrapper_data_collector.data_collector import (
    collect_pods_data,
    collect_resources_yaml_instance,
    get_data_collector_base_dir,
    prepare_pytest_item_data_dir,
    write_to_file,
)
from pytest_testconfig import config as py_config

import utilities.infra
from utilities.constants import MACHINE_CONFIG_PODS_TO_COLLECT, VIRT_LAUNCHER


LOGGER = logging.getLogger(__name__)


def collect_alerts_data(prometheus):
    data_collector_dict = get_data_collector_dict()
    base_directory = get_data_collector_base_dir(
        data_collector_dict=data_collector_dict
    )
    LOGGER.warning(f"Base directory: {base_directory}")
    alerts = prometheus.alerts["data"].get("alerts")
    write_to_file(
        base_directory=base_directory,
        file_name="firing_alerts.json",
        content=json.dumps(alerts),
    )


def collect_mcp_information():
    data_collector_dict = get_data_collector_dict()
    base_directory = get_data_collector_base_dir(
        data_collector_dict=data_collector_dict
    )
    LOGGER.warning("Collecting MachineConfigPool data for triage.")
    collect_resources_yaml_instance(
        resources_to_collect=[MachineConfigPool, Node], base_directory=base_directory
    )

    pods_to_collect = []
    for pod_prefix in MACHINE_CONFIG_PODS_TO_COLLECT:
        pods_to_collect.extend(
            utilities.infra.get_pod_by_name_prefix(
                dyn_client=get_client(),
                pod_prefix=pod_prefix,
                namespace="openshift-machine-config-operator",
                get_all=True,
            )
        )
    collect_pods_data(pods_list=pods_to_collect, base_directory=base_directory)


def collect_cnv_information():
    data_collector_dict = get_data_collector_dict()
    base_directory = get_data_collector_base_dir(
        data_collector_dict=data_collector_dict
    )
    LOGGER.warning("Collecting CNV pod and HCO data for triage.")
    collect_resources_yaml_instance(
        resources_to_collect=[HyperConverged, KubeVirt], base_directory=base_directory
    )

    pods_to_collect = [
        pod
        for pod in cluster_resource(Pod).get(
            dyn_client=get_client(), namespace=py_config["hco_namespace"]
        )
    ]
    collect_pods_data(pods_list=pods_to_collect, base_directory=base_directory)


def collect_virt_launcher_pod_data():
    base_directory = get_data_collector_base_dir(
        data_collector_dict=get_data_collector_dict()
    )
    LOGGER.warning("Collecting virt-launcher pods for all namespace.")
    pods_to_collect = list(
        Pod.get(
            dyn_client=get_client(),
            label_selector=f"{Pod.ApiGroup.KUBEVIRT_IO}={VIRT_LAUNCHER}",
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
