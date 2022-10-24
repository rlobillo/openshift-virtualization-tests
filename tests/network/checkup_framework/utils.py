import contextlib
import logging

import packaging.version
import pytest
from ocp_resources.configmap import ConfigMap
from ocp_resources.job import Job
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from ocp_utilities.infra import cluster_resource
from pytest_testconfig import py_config

from utilities.constants import TIMEOUT_1MIN, TIMEOUT_5MIN
from utilities.infra import get_pods


LOGGER = logging.getLogger(__name__)
LATENCY_CONFIGMAP = "latency-configmap"
CHECKUP_FRAMEWORK_NAMESPACE = "kiagnose"


@contextlib.contextmanager
def create_latency_job(service_account, cnv_current_version, name=None):
    current_version = packaging.version.parse(version=cnv_current_version).base_version
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
                    f"container-native-virtualization-checkup-framework:v{current_version}"
                ),
                "imagePullPolicy": "Always",
                "env": [
                    {
                        "name": "CONFIGMAP_NAMESPACE",
                        "value": service_account.namespace,
                    },
                    {"name": "CONFIGMAP_NAME", "value": LATENCY_CONFIGMAP},
                ],
            }
        ],
    ) as job:
        yield job


@contextlib.contextmanager
def create_latency_configmap(framework_service_account, cnv_current_version, **kwargs):
    data = compose_configmap_data(
        framework_service_account=framework_service_account,
        cnv_current_version=cnv_current_version,
        **kwargs,
    )
    with cluster_resource(ConfigMap)(
        namespace=framework_service_account.namespace, name=LATENCY_CONFIGMAP, data=data
    ) as configmap:
        yield configmap


@contextlib.contextmanager
def create_checkup_resources(framework_service_account, cnv_current_version, **kwargs):
    data = compose_configmap_data(
        framework_service_account=framework_service_account,
        cnv_current_version=cnv_current_version,
        *kwargs,
    )
    with cluster_resource(ConfigMap)(
        namespace=framework_service_account.namespace, name=LATENCY_CONFIGMAP, data=data
    ) as configmap:
        with create_latency_job(
            latency_configmap=configmap,
            service_account=framework_service_account,
            cnv_current_version=cnv_current_version,
        ) as job:
            yield {"job": job, "configmap": configmap}


def compose_configmap_data(
    framework_service_account,
    cnv_current_version,
    image="container-native-virtualization-vm-network-latency-checkup",
    timeout=f"{TIMEOUT_5MIN}m",
    cluster_role=None,
    **kwargs,
):
    current_version = packaging.version.parse(version=cnv_current_version).base_version
    data_dict = {
        "spec.image": f"{py_config['cnv_registry_sources']['osbs']['source_map']}/{image+':v'+current_version}",
        "spec.timeout": timeout,
        "spec.serviceAccountName": framework_service_account.name,
    }
    if cluster_role:
        data_dict["spec.clusterRoles"] = cluster_role
    for key in kwargs:
        data_dict[f"spec.param.{key}"] = kwargs[key]

    return data_dict


def assert_successful_checkup(configmap, job):
    try:
        job.wait_for_condition(
            condition=job.Condition.COMPLETE, status=job.Condition.Status.TRUE
        )
        configmap_data = configmap.instance.data
        assert (
            "true" in configmap_data["status.succeeded"]
        ), f"Checkup failed. Reported reason - {configmap_data['status.failureReason']}"
    except TimeoutExpiredError:
        LOGGER.error(
            f"Couldn't run checkup. Framework job failed. status - {job.instance.status}"
        )
        raise


def assert_checkup_timeout(configmap, job):
    """
    Negative framework test cases should reach timeout on successful runs
    """
    with pytest.raises(TimeoutExpiredError):
        assert_successful_checkup(configmap=configmap, job=job)


def get_job_status(job):
    sample = None
    sampler = TimeoutSampler(
        wait_timeout=TIMEOUT_1MIN,
        sleep=1,
        func=lambda: job.instance.status.conditions[0]["type"],
    )
    try:
        for sample in sampler:
            if sample:
                return sample
    except TimeoutExpiredError:
        LOGGER.error(
            f"Current job {job.name} status type cannot be retrieved. Current job status - {sample}"
        )
        raise


def assert_configmap_in_use(admin_client, job, framework_ns):
    job_status = get_job_status(job=job)
    assert job_status == job.Status.FAILED, (
        f"Job {job.name} current status is {job_status} and not "
        f"{job.Status.FAILED} as expected."
    )

    concurrent_job_pod = None
    for pod in get_pods(
        dyn_client=admin_client,
        namespace=framework_ns,
        label=f"job-name={job.name}",
    ):
        concurrent_job_pod = pod
        command_output = concurrent_job_pod.log()
        error_message = "configMap is already in use"
        assert (
            error_message in command_output
        ), f"Error message expected: {error_message}. Error message received: {command_output}."
    assert concurrent_job_pod, "No pod found for concurrent job"
