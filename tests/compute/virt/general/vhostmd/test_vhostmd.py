import logging

import pytest
import xmltodict
from ocp_resources.resource import Resource
from ocp_utilities.utils import run_ssh_commands
from pytest_testconfig import config as py_config

from tests.os_params import RHEL_LATEST, RHEL_LATEST_LABELS, RHEL_LATEST_OS
from utilities.constants import RHSM_PASSWD, RHSM_USER, TIMEOUT_3MIN
from utilities.virt import (
    prepare_cloud_init_user_data,
    running_vm,
    vm_instance_from_template,
)


pytestmark = pytest.mark.post_upgrade

LOGGER = logging.getLogger(__name__)


@pytest.fixture()
def vhostmd_vm1(
    request,
    unprivileged_client,
    namespace,
    golden_image_data_source_scope_function,
    schedulable_nodes,
):
    with vm_instance_from_template(
        request=request,
        unprivileged_client=unprivileged_client,
        namespace=namespace,
        data_source=golden_image_data_source_scope_function,
        node_selector=schedulable_nodes[0].name,
        cloud_init_data=rhsm_and_vmdumpmetrics_pkg_cloud_init_data(),
    ) as vhostmd_vm1:
        vhostmd_vm1.start()
        yield vhostmd_vm1


@pytest.fixture()
def vhostmd_vm2(
    request,
    unprivileged_client,
    namespace,
    golden_image_data_source_scope_function,
    schedulable_nodes,
):
    with vm_instance_from_template(
        request=request,
        unprivileged_client=unprivileged_client,
        namespace=namespace,
        data_source=golden_image_data_source_scope_function,
        node_selector=schedulable_nodes[0].name,
        cloud_init_data=rhsm_and_vmdumpmetrics_pkg_cloud_init_data(),
    ) as vhostmd_vm2:
        vhostmd_vm2.start()
        yield vhostmd_vm2


@pytest.fixture()
def running_vhostmd_vm1(vhostmd_vm1):
    return running_vm(vm=vhostmd_vm1, ssh_timeout=TIMEOUT_3MIN)


@pytest.fixture()
def running_vhostmd_vm2(vhostmd_vm2):
    return running_vm(vm=vhostmd_vm2, ssh_timeout=TIMEOUT_3MIN)


def run_vm_dump_metrics(vm):
    return run_ssh_commands(
        host=vm.ssh_exec,
        commands=["sudo", "vm-dump-metrics"],
    )[0]


def rhsm_and_vmdumpmetrics_pkg_cloud_init_data():
    bootcmds = [
        "sudo subscription-manager config --rhsm.auto_enable_yum_plugins=0",
        (
            "sudo subscription-manager register "
            "--serverurl=subscription.rhsm.stage.redhat.com:443/subscription "
            "--baseurl=https://cdn.stage.redhat.com "
            f"--username={RHSM_USER} "
            f"--password={RHSM_PASSWD} "
            "--auto-attach"
        ),
        "sudo yum install -y vm-dump-metrics",
    ]
    return prepare_cloud_init_user_data(section="bootcmd", data=bootcmds)


@pytest.mark.parametrize(
    "golden_image_data_volume_scope_function, vhostmd_vm1, vhostmd_vm2,",
    [
        pytest.param(
            {
                "dv_name": RHEL_LATEST_OS,
                "image": RHEL_LATEST["image_path"],
                "storage_class": py_config["default_storage_class"],
                "dv_size": RHEL_LATEST["dv_size"],
            },
            {
                "vm_name": "vhostmd1",
                "vhostmd": True,
                "template_labels": RHEL_LATEST_LABELS,
                "start_vm": False,
            },
            {
                "vm_name": "vhostmd2",
                "vhostmd": True,
                "template_labels": RHEL_LATEST_LABELS,
                "start_vm": False,
            },
        ),
    ],
    indirect=True,
)
@pytest.mark.polarion("CNV-6547")
def test_vhostmd_disk(
    skip_upstream,
    vhostmd_vm1,
    vhostmd_vm2,
    running_vhostmd_vm1,
    running_vhostmd_vm2,
):
    assert vhostmd_vm1.node_selector == vhostmd_vm2.node_selector, (
        f"Both the VM's should be running on the same node. "
        f"The  VM {vhostmd_vm1.name} runs on {vhostmd_vm1.node_selector} and "
        f"{vhostmd_vm2.name} runs on {vhostmd_vm2.node_selector}"
    )
    expected_vendor_metric_name = "VirtualizationVendor"
    expected_vendor_metric_value = Resource.ApiGroup.KUBEVIRT_IO
    expected_host_metric_name = "HostName"
    for vm in [vhostmd_vm1, vhostmd_vm2]:
        expected_host_metric_value = vm.node_selector
        all_metric_names = []
        for metric in xmltodict.parse(xml_input=run_vm_dump_metrics(vm=vm))["metrics"][
            "metric"
        ]:
            # Gather all the metric names available from vm-dump-metrics.
            for value in metric.values():
                if metric["name"]:
                    all_metric_names.append(value)
            metric_name = metric["name"]
            metric_value = metric["value"]
            if metric_name == expected_vendor_metric_name:
                assert metric_value == expected_vendor_metric_value, (
                    f"Expected: vhostmd should have {expected_vendor_metric_name} as {expected_vendor_metric_value}."
                    f"Actual: vhostmd has {metric_name} as {metric_value}."
                )
            if metric_name == expected_host_metric_name:
                assert metric_value == expected_host_metric_value, (
                    f"Expected: The VMI: {vm.name} with metric name: {expected_host_metric_name} "
                    f"should match {expected_host_metric_value}"
                    f"Actual: The VMI: {vm.name} with metric name: {metric_name} has the value {metric_value}"
                )
        assert (
            expected_vendor_metric_name in all_metric_names
        ), f"vm-dump-metrics output {all_metric_names} does not contain {expected_vendor_metric_name}"
        assert (
            expected_host_metric_name in all_metric_names
        ), f"vm-dump-metrics output {all_metric_names} does not contain {expected_host_metric_name}"
