import contextlib
import logging

import pytest
from ocp_resources.configmap import ConfigMap
from ocp_resources.job import Job
from ocp_resources.utils import TimeoutExpiredError
from pytest_testconfig import py_config

from utilities.constants import TIMEOUT_5MIN
from utilities.infra import cluster_resource


LOGGER = logging.getLogger(__name__)
LATENCY_CONFIGMAP = "latency-configmap"


@contextlib.contextmanager
def create_latency_job(service_account, name=None):
    with Job(
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
                    "container-native-virtualization-checkup-framework"
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
def create_latency_configmap(framework_service_account, **kwargs):
    data = compose_configmap_data(
        framework_service_account=framework_service_account, **kwargs
    )
    with cluster_resource(ConfigMap)(
        namespace=framework_service_account.namespace, name=LATENCY_CONFIGMAP, data=data
    ) as configmap:
        yield configmap


@contextlib.contextmanager
def create_checkup_resources(framework_service_account, **kwargs):
    data = compose_configmap_data(
        framework_service_account=framework_service_account, **kwargs
    )
    with cluster_resource(ConfigMap)(
        namespace=framework_service_account.namespace, name=LATENCY_CONFIGMAP, data=data
    ) as configmap:
        with create_latency_job(
            latency_configmap=configmap, service_account=framework_service_account
        ) as job:
            yield {"job": job, "configmap": configmap}


def compose_configmap_data(
    framework_service_account,
    image="container-native-virtualization-vm-network-latency-checkup",
    timeout=f"{TIMEOUT_5MIN}m",
    cluster_role=None,
    **kwargs,
):
    data_dict = {
        "spec.image": f"{py_config['cnv_registry_sources']['osbs']['source_map']}/{image}",
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
