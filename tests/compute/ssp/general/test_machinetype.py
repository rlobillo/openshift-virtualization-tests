# -*- coding: utf-8 -*-
import logging
import re
import shlex

import pytest
from openshift.dynamic.exceptions import UnprocessibleEntityError
from pyhelper_utils.shell import run_ssh_commands
from pytest_testconfig import py_config

from tests.compute.ssp.constants import MachineTypesNames
from tests.os_params import (
    RHEL_6_10_TEMPLATE_LABELS,
    RHEL_7_8,
    RHEL_7_8_TEMPLATE_LABELS,
)
from utilities.hco import update_hco_annotations
from utilities.infra import cluster_resource
from utilities.virt import (
    VirtualMachineForTests,
    fedora_vm_body,
    migrate_vm_and_verify,
    restart_vm_wait_for_running_vm,
    running_vm,
    wait_for_updated_kv_value,
)


pytestmark = pytest.mark.post_upgrade
LOGGER = logging.getLogger(__name__)


def validate_machine_type(expected_machine_type, vm):
    vm_machine_type = vm.instance.spec.template.spec.domain.machine.type
    vmi_machine_type = vm.vmi.instance.spec.domain.machine.type

    assert vm_machine_type == vmi_machine_type == expected_machine_type, (
        f"Created VM's machine type does not match the request. "
        f"Expected: {expected_machine_type} VM: {vm_machine_type}, VMI: {vmi_machine_type}"
    )

    vmi_xml_machine_type = vm.vmi.xml_dict["domain"]["os"]["type"]["@machine"]
    assert (
        vmi_xml_machine_type == expected_machine_type
    ), f"libvirt machine type {vmi_xml_machine_type} does not match expected type {expected_machine_type}"


def validate_cpu_chip_version(expected_machine_type, vm):
    LOGGER.info(
        f"Validating cpu chip version of vm to expected value: {expected_machine_type}."
    )
    expected_machine_info = re.search(
        r"((?P<type>.*?)-)?(?P<model>.*)-(?P<os_name>\D*)(?P<os_version>.*)",
        expected_machine_type,
    ).groupdict()
    linux_vm_lshw_cpu_version = run_ssh_commands(
        host=vm.ssh_exec,
        commands=[shlex.split("sudo /sbin/lshw -C cpu | grep version")],
    )[0].lower()
    linux_vm_lshw_machine_info = re.search(
        r"(?<=: )(?P<os_name>.*?)(-|\s)(?P<os_version>\S*)(\s(?P<type>\S*))?\s\((?P<model>\S*)",
        linux_vm_lshw_cpu_version,
    ).groupdict()
    assert expected_machine_info == linux_vm_lshw_machine_info, (
        f"vm cpu version info: {linux_vm_lshw_machine_info}, "
        f"does not match expected machine info: {expected_machine_info}"
    )


@pytest.fixture()
def vm(request, cluster_cpu_model_scope_function, unprivileged_client, namespace):
    name = f"vm-{request.param['vm_name']}-machine-type"

    with cluster_resource(VirtualMachineForTests)(
        name=name,
        namespace=namespace.name,
        body=fedora_vm_body(name=name),
        client=unprivileged_client,
        machine_type=request.param.get("machine_type"),
    ) as vm:
        running_vm(vm=vm, check_ssh_connectivity=False)
        yield vm


@pytest.fixture()
def updated_configmap_machine_type(
    request,
    hyperconverged_resource_scope_function,
    kubevirt_config,
    admin_client,
    hco_namespace,
):
    machine_type = request.param["machine_type"]
    with update_hco_annotations(
        resource=hyperconverged_resource_scope_function,
        path="machineType",
        value=machine_type,
    ):
        wait_for_updated_kv_value(
            admin_client=admin_client,
            hco_namespace=hco_namespace,
            path=["machineType"],
            value=machine_type,
        )
        yield


@pytest.fixture()
def updated_hco_emulated_machine_i440fx(
    hyperconverged_resource_scope_function,
    admin_client,
    hco_namespace,
):
    annotations_path = "emulatedMachines"
    with update_hco_annotations(
        resource=hyperconverged_resource_scope_function,
        path=annotations_path,
        value=[MachineTypesNames.pc_i440fx],
    ):
        wait_for_updated_kv_value(
            admin_client=admin_client,
            hco_namespace=hco_namespace,
            path=[annotations_path],
            value=[MachineTypesNames.pc_i440fx],
        )
        yield


@pytest.mark.parametrize(
    "vm",
    [
        pytest.param(
            {"vm_name": "default"},
            marks=pytest.mark.polarion("CNV-3312"),
        )
    ],
    indirect=True,
)
def test_default_machine_type(machine_type_from_kubevirt_config, vm):
    validate_machine_type(
        vm=vm, expected_machine_type=machine_type_from_kubevirt_config
    )


@pytest.mark.parametrize(
    "vm, expected",
    [
        pytest.param(
            {"vm_name": "pc-q35", "machine_type": MachineTypesNames.pc_q35_rhel7_6},
            MachineTypesNames.pc_q35_rhel7_6,
            marks=pytest.mark.polarion("CNV-3311"),
        )
    ],
    indirect=["vm"],
)
def test_pc_q35_vm_machine_type(vm, expected):
    validate_machine_type(vm=vm, expected_machine_type=expected)


@pytest.mark.parametrize(
    "vm",
    [
        pytest.param(
            {"vm_name": "machine-type-mig"},
            marks=pytest.mark.polarion("CNV-3323"),
        )
    ],
    indirect=True,
)
def test_migrate_vm(
    machine_type_from_kubevirt_config,
    vm,
):
    migrate_vm_and_verify(vm=vm)

    validate_machine_type(
        vm=vm, expected_machine_type=machine_type_from_kubevirt_config
    )


@pytest.mark.parametrize(
    "vm, updated_configmap_machine_type",
    [
        pytest.param(
            {"vm_name": "default-cm"},
            {"machine_type": MachineTypesNames.pc_q35_rhel8_1},
            marks=pytest.mark.polarion("CNV-4347"),
        )
    ],
    indirect=True,
)
def test_machine_type_after_cm_update(
    machine_type_from_kubevirt_config,
    vm,
    updated_configmap_machine_type,
):
    """Test machine type change in ConfigMap; existing VM does not get new
    value after restart or migration"""

    validate_machine_type(
        vm=vm, expected_machine_type=machine_type_from_kubevirt_config
    )

    restart_vm_wait_for_running_vm(vm=vm, check_ssh_connectivity=False)
    validate_machine_type(
        vm=vm, expected_machine_type=machine_type_from_kubevirt_config
    )

    migrate_vm_and_verify(vm=vm)

    validate_machine_type(
        vm=vm, expected_machine_type=machine_type_from_kubevirt_config
    )


@pytest.mark.parametrize(
    "vm, updated_configmap_machine_type",
    [
        pytest.param(
            {"vm_name": "updated-cm"},
            {"machine_type": MachineTypesNames.pc_q35_rhel8_1},
            marks=pytest.mark.polarion("CNV-3681"),
        )
    ],
    indirect=True,
)
def test_machine_type_cm_update(updated_configmap_machine_type, vm):
    """Test machine type change in ConfigMap; new VM gets new value"""

    validate_machine_type(vm=vm, expected_machine_type=MachineTypesNames.pc_q35_rhel8_1)


@pytest.mark.polarion("CNV-3688")
def test_unsupported_machine_type(namespace, unprivileged_client):
    vm_name = "vm-invalid-machine-type"

    with pytest.raises(UnprocessibleEntityError):
        with cluster_resource(VirtualMachineForTests)(
            name=vm_name,
            namespace=namespace.name,
            body=fedora_vm_body(name=vm_name),
            client=unprivileged_client,
            machine_type=MachineTypesNames.pc_i440fx_rhel7_6,
        ):
            pytest.fail("VM created with invalid machine type.")


@pytest.mark.polarion("CNV-5658")
def test_major_release_machine_type(machine_type_from_kubevirt_config):
    # CNV should always use a major release for machine type, for example: pc-q35-rhel8.3.0
    assert machine_type_from_kubevirt_config.endswith(
        ".0"
    ), f"Machine type should be a major release {machine_type_from_kubevirt_config}"


@pytest.mark.parametrize(
    "golden_image_data_volume_scope_function, "
    "vm_from_template_scope_function, "
    "expected_machine_type",
    [
        pytest.param(
            {
                "dv_name": RHEL_7_8_TEMPLATE_LABELS["os"],
                "image": RHEL_7_8["image_path"],
                "dv_size": RHEL_7_8["dv_size"],
                "storage_class": py_config["default_storage_class"],
            },
            {
                "vm_name": "legacy-vm",
                "template_labels": RHEL_6_10_TEMPLATE_LABELS,
                "machine_type": MachineTypesNames.pc_i440fx_rhel7_6,
            },
            MachineTypesNames.pc_i440fx_rhel7_6,
            marks=pytest.mark.polarion("CNV-7311"),
        )
    ],
    indirect=[
        "golden_image_data_volume_scope_function",
        "vm_from_template_scope_function",
    ],
)
def test_legacy_machine_type(
    updated_hco_emulated_machine_i440fx,
    golden_image_data_volume_scope_function,
    vm_from_template_scope_function,
    expected_machine_type,
):
    validate_machine_type(
        vm=vm_from_template_scope_function,
        expected_machine_type=expected_machine_type,
    )
    validate_cpu_chip_version(
        vm=vm_from_template_scope_function,
        expected_machine_type=expected_machine_type,
    )


@pytest.mark.polarion("CNV-8561")
def test_machine_type_as_rhel_8_6(machine_type_from_kubevirt_config):
    """Verify that machine type im KubeVirt CR match the value pc-q35-rhel8.6.0"""
    assert machine_type_from_kubevirt_config == MachineTypesNames.pc_q35_rhel8_6, (
        f"Machine type value is {machine_type_from_kubevirt_config}"
        f"does not match with {MachineTypesNames.pc_q35_rhel8_6}"
    )
