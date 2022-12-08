import contextlib
import logging
import re

from ocp_resources.configmap import ConfigMap
from ocp_resources.job import Job
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from ocp_utilities.infra import cluster_resource
from pytest_testconfig import py_config

from utilities.constants import TIMEOUT_4MIN, TIMEOUT_5MIN
from utilities.infra import get_pods


LOGGER = logging.getLogger(__name__)
CHECKUP_FRAMEWORK_NAMESPACE = "kiagnose"
MAX_DESIRED_LATENCY_MILLISECONDS = "15"
LATENCY_CONFIGMAP = "latency-configmap"


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
    namespace_name,
    max_desired_latency_milliseconds=MAX_DESIRED_LATENCY_MILLISECONDS,
    sample_duration_seconds="5",
    timeout=f"{TIMEOUT_5MIN}m",
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
        namespace=namespace_name, name=LATENCY_CONFIGMAP, data=data
    ) as configmap:
        yield configmap


def compose_configmap_data(
    network_attachment_definition_namespace,
    network_attachment_definition_name,
    max_desired_latency_milliseconds,
    sample_duration_seconds,
    timeout,
    source_node,
    target_node,
):
    """
    Compose a dictionary with the ConfigMap data.

    Args:
        network_attachment_definition_namespace (str): Namespace name where the NAD was created.
        network_attachment_definition_name (str): NAD name.
        max_desired_latency_milliseconds (str): Maximum desired latency between VMs. If the latency is higher than
            this - the checkup fails. This value should be given in milliseconds.
        sample_duration_seconds (str): Latency check duration, in seconds.
        timeout (str): Timeout to wait for the checkup to finish, in minutes.
        source_node (str): Node hostname. Check latency from this node to the target_node.
        target_node (str): Node hostname. Check latency from source_node to this node.

    Returns:
        dict: Data section of the ConfigMap.
    """
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


def assert_successful_checkup(unprivileged_client, configmap, job):
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
        pod_last_log_line = get_pod_last_log_line(
            unprivileged_client=unprivileged_client,
            job=job,
            checkup_ns=configmap.namespace,
        )
        LOGGER.error(
            f"Couldn't run checkup. Framework job failed. status - {job.instance.status}. \n Error massage - last "
            f"line from the pod log: {pod_last_log_line}"
        )
        raise


def wait_for_job_failure(job):
    try:
        job_status = TimeoutSampler(
            wait_timeout=TIMEOUT_4MIN,
            sleep=1,
            func=lambda: job.instance.status.conditions[0],
        )
        for sample in job_status:
            if (
                sample["type"] == job.Status.FAILED
                and sample["status"] == job.Condition.Status.TRUE
            ):
                return
    except TimeoutExpiredError:
        LOGGER.error(
            f"Job {job.name} current status is {job_status} and not {job.Status.FAILED} as expected."
        )
        raise


def get_pod_last_log_line(unprivileged_client, job, checkup_ns):
    for job_pod in get_pods(
        dyn_client=unprivileged_client,
        namespace=checkup_ns,
        label=f"job-name={job.name}",
    ):
        return job_pod.log(tail_lines=1)


def verify_failure_reason_in_log(unprivileged_client, job, checkup_ns, failure_message):
    pod_last_log_line = get_pod_last_log_line(
        unprivileged_client=unprivileged_client, job=job, checkup_ns=checkup_ns
    )
    assert (
        failure_message in pod_last_log_line
    ), f"Error message expected: {failure_message}. Error message received: {pod_last_log_line}."


def assert_identical_source_and_target_node(configmap):
    configmap_instance_data = configmap.instance.data
    source_node = configmap_instance_data["status.result.sourceNode"]
    target_node = configmap_instance_data["status.result.targetNode"]
    assert source_node == target_node, (
        "Target and source nodes are not identical: "
        f"Source node: {source_node}, Target node: {target_node}"
    )


def assert_failure_reason_in_configmap(configmap, expected_failure_message):
    failure_message = configmap.instance.data["status.failureReason"]
    assert re.findall(expected_failure_message, failure_message), (
        f"Failure massage is {failure_message} and not as "
        f"expected: {expected_failure_message}"
    )
