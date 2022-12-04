import contextlib
import logging

from ocp_resources.configmap import ConfigMap
from ocp_resources.job import Job
from ocp_resources.utils import TimeoutExpiredError
from ocp_utilities.infra import cluster_resource
from pytest_testconfig import py_config

from utilities.constants import TIMEOUT_5MIN


LOGGER = logging.getLogger(__name__)
CHECKUP_FRAMEWORK_NAMESPACE = "kiagnose"
MAX_DESIRED_LATENCY_MILLISECONDS = "15"


@contextlib.contextmanager
def create_latency_job(
    service_account, cnv_current_version, latency_configmap_name, name=None
):
    with cluster_resource(Job)(
        name=name or "latency-job",
        namespace=service_account.namespace,
        service_account=service_account.name,
        restart_policy="Never",
        backoff_limit=0,
        containers=[
            {
                "name": "framework",
                "image": (
                    f"{py_config['cnv_registry_sources']['osbs']['source_map']}/"
                    f"container-native-virtualization-vm-network-latency-checkup:v{cnv_current_version}"
                ),
                "imagePullPolicy": "Always",
                "env": [
                    {
                        "name": "CONFIGMAP_NAMESPACE",
                        "value": service_account.namespace,
                    },
                    {"name": "CONFIGMAP_NAME", "value": latency_configmap_name},
                ],
            }
        ],
    ) as job:
        yield job


@contextlib.contextmanager
def create_latency_configmap(
    network_attachment_definition_namespace,
    network_attachment_definition_name,
    namespace,
    timeout=f"{TIMEOUT_5MIN}m",
    max_desired_latency_milliseconds=MAX_DESIRED_LATENCY_MILLISECONDS,
    sample_duration_seconds="5",
    source_node=None,
    target_node=None,
):
    data = compose_configmap_data(
        timeout=timeout,
        network_attachment_definition_namespace=network_attachment_definition_namespace,
        network_attachment_definition_name=network_attachment_definition_name,
        max_desired_latency_milliseconds=max_desired_latency_milliseconds,
        sample_duration_seconds=sample_duration_seconds,
        source_node=source_node,
        target_node=target_node,
    )
    with cluster_resource(ConfigMap)(
        namespace=namespace, name="latency-configmap", data=data
    ) as configmap:
        yield configmap


def compose_configmap_data(
    timeout,
    network_attachment_definition_namespace,
    network_attachment_definition_name,
    max_desired_latency_milliseconds,
    sample_duration_seconds,
    source_node,
    target_node,
):
    data_dict = {
        "spec.timeout": timeout,
        "spec.param.network_attachment_definition_namespace": network_attachment_definition_namespace,
        "spec.param.network_attachment_definition_name": network_attachment_definition_name,
        "spec.param.max_desired_latency_milliseconds": max_desired_latency_milliseconds,
        "spec.param.sample_duration_seconds": sample_duration_seconds,
    }
    if source_node:
        data_dict["spec.param.source_node"] = source_node
    if target_node:
        data_dict["spec.param.target_node"] = target_node

    return data_dict


def assert_successful_checkup(configmap, job):
    try:
        job.wait_for_condition(
            condition=job.Condition.COMPLETE, status=job.Condition.Status.TRUE
        )
        configmap_data = configmap.instance.to_dict()["data"]
        assert (
            configmap_data["status.succeeded"] == "true"
        ), f"Checkup failed. Reported reason - {configmap_data['status.failureReason']}"
        # Make sure the result parameter are valid:
        assert (
            int(configmap_data["status.result.avgLatencyNanoSec"]) > 0
        ), f"avgLatencyNanoSec is not valid: {configmap_data['status.result.avgLatencyNanoSec']}"
        assert int(configmap_data["status.result.maxLatencyNanoSec"]) > 0, (
            f"maxLatencyNanoSec is not valid:"
            f" {configmap_data['status.result.maxLatencyNanoSec']}"
        )
        assert int(configmap_data["status.result.maxLatencyNanoSec"]) / 1000000 < int(
            MAX_DESIRED_LATENCY_MILLISECONDS
        ), f"maxLatencyNanoSec is not valid: {configmap_data['status.result.maxLatencyNanoSec']}"
        assert (
            int(configmap_data["status.result.minLatencyNanoSec"]) > 0
        ), f"minLatencyNanoSec is not valid: {configmap_data['status.result.minLatencyNanoSec']}"
    except TimeoutExpiredError:
        LOGGER.error(
            f"Couldn't run checkup. Framework job failed. status - {job.instance.status}"
        )
        raise
