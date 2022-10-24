import logging

import pytest
from ocp_resources.resource import Resource
from ocp_utilities.infra import cluster_resource
from pytest_testconfig import config as py_config

from tests.install_upgrade_operators.metrics.utils import (
    validate_vm_vcpu_cpu_affinity_with_prometheus,
)
from tests.os_params import RHEL_LATEST, RHEL_LATEST_LABELS, RHEL_LATEST_OS
from utilities.virt import VirtualMachineForTests, fedora_vm_body, running_vm


KUBEVIRT_VM_TAG = f"{Resource.ApiGroup.KUBEVIRT_IO}/vm"
LOGGER = logging.getLogger(__name__)


@pytest.fixture(scope="class")
def fedora_vm_without_name_in_label(
    namespace,
    unprivileged_client,
):
    vm_name = "test-vm-label-fedora-vm"
    vm_body = fedora_vm_body(name=vm_name)
    virt_launcher_pod_labels = vm_body["spec"]["template"]["metadata"].get("labels")
    vm_label = vm_body["metadata"].get("labels")

    # Remove the label 'kubevirt.io/vm' from virt-launcher pod labels, if present
    if virt_launcher_pod_labels and virt_launcher_pod_labels.get(KUBEVIRT_VM_TAG):
        del virt_launcher_pod_labels[KUBEVIRT_VM_TAG]

    if vm_label and vm_label.get(KUBEVIRT_VM_TAG):
        del vm_label[KUBEVIRT_VM_TAG]

    # Create VM, after removal of label 'kubevirt.io/vm' from virt-launcher pod
    with cluster_resource(VirtualMachineForTests)(
        name=vm_name,
        namespace=namespace.name,
        body=vm_body,
        client=unprivileged_client,
        running=True,
    ) as vm:
        running_vm(vm=vm, check_ssh_connectivity=False)
        LOGGER.info(f"VM with the name {vm.name} is UP")
        yield vm


@pytest.mark.parametrize(
    "golden_image_data_volume_scope_class, vm_from_template",
    [
        pytest.param(
            {
                "dv_name": RHEL_LATEST_OS,
                "image": RHEL_LATEST["image_path"],
                "storage_class": py_config["default_storage_class"],
                "dv_size": RHEL_LATEST["dv_size"],
            },
            {
                "vm_name": "rhel-latest",
                "template_labels": RHEL_LATEST_LABELS,
                "guest_agent": False,
                "ssh": False,
            },
        ),
    ],
    indirect=True,
)
class TestVMICPUAffinity:
    @pytest.mark.polarion("CNV-7295")
    def test_kubevirt_vmi_cpu_affinity(
        self, prometheus, schedulable_nodes, vm_from_template
    ):
        """This test will check affinity of vcpu and cpu from query and VM."""
        validate_vm_vcpu_cpu_affinity_with_prometheus(
            vm=vm_from_template,
            prometheus=prometheus,
            nodes=schedulable_nodes,
            query=f'kubevirt_vmi_cpu_affinity{{kubernetes_vmi_label_kubevirt_io_domain="{vm_from_template.name}"}}',
        )


class TestVMNameInLabel:
    @pytest.mark.polarion("CNV-8582")
    def test_vm_name_in_virt_launcher_label(self, fedora_vm_without_name_in_label):
        """
        when VM created from vm.yaml,for the kind=VirtualMachine, doesn't have
        the VM name in label, then virt-launcher pod should have the
        VM name in the label populated automatically
        """
        # Get the label of virt-launcher pod
        virt_launcher_pod_labels = (
            fedora_vm_without_name_in_label.vmi.virt_launcher_pod.labels
        )
        vm_name = fedora_vm_without_name_in_label.name
        assert (
            virt_launcher_pod_labels.get(f"{Resource.ApiGroup.VM_KUBEVIRT_IO}/name")
            == vm_name
        ), (
            f"VM name {vm_name} is missing in the virt-launcher pod label"
            f"Content of virt-launcher pod label: {virt_launcher_pod_labels}"
        )
