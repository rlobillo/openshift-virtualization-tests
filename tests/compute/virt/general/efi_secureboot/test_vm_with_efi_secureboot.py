"""
EFI secureBoot VM
"""

import logging
import os
import shlex

import pytest
from ocp_resources.resource import ResourceEditor
from ocp_resources.template import Template
from ocp_utilities.utils import run_ssh_commands
from openshift.dynamic.exceptions import UnprocessibleEntityError
from pytest_testconfig import config as py_config

from tests.compute.utils import (
    assert_vm_xml_efi,
    assert_windows_efi,
    validate_linux_efi,
)
from utilities.constants import OS_FLAVOR_RHEL, TIMEOUT_5MIN, Images
from utilities.infra import cluster_resource
from utilities.virt import (
    VirtualMachineForTests,
    VirtualMachineForTestsFromTemplate,
    migrate_vm_and_verify,
    restart_vm_wait_for_running_vm,
    running_vm,
)


LOGGER = logging.getLogger(__name__)
VM_CPU = 2
VM_MEMORY = 1
RHEL_EFI_IMG = os.path.join(Images.Rhel.DIR, Images.Rhel.RHEL8_2_EFI_IMG)
WIN_EFI_IMG = os.path.join(Images.Windows.DIR, Images.Windows.WIM10_EFI_IMG)


@pytest.fixture(scope="class")
def rhel_efi_secureboot_vm(
    cluster_cpu_model_scope_class,
    namespace,
    unprivileged_client,
    data_volume_scope_class,
):
    """Create VM with EFI secureBoot set as True"""
    with cluster_resource(VirtualMachineForTests)(
        name="rhel-efi-secureboot-default",
        namespace=namespace.name,
        client=unprivileged_client,
        data_volume=data_volume_scope_class,
        cpu_cores=VM_CPU,
        memory_requests=f"{VM_MEMORY}Gi",
        smm_enabled=True,
        efi_params={"secureBoot": True},
        os_flavor=OS_FLAVOR_RHEL,
    ) as vm:
        running_vm(vm=vm)
        yield vm


@pytest.fixture(scope="class")
def windows_efi_secureboot_vm(
    cluster_cpu_model_scope_class,
    namespace,
    unprivileged_client,
    golden_image_data_source_scope_class,
):
    """Create VM with EFI secureBoot set as True"""
    with VirtualMachineForTestsFromTemplate(
        name="windows-efi-secureboot",
        namespace=namespace.name,
        client=unprivileged_client,
        labels=Template.generate_template_labels(
            **py_config["system_windows_os_matrix"][0]["win-10"]["template_labels"]
        ),
        data_source=golden_image_data_source_scope_class,
        cpu_cores=VM_CPU,
        smm_enabled=True,
        efi_params={"secureBoot": True},
    ) as vm:
        # EFI Windows OS takes longer to be up and connective
        # TODO: remove wait_for_interfaces=False when Windows EFI image is updated
        running_vm(vm=vm, wait_for_interfaces=False, ssh_timeout=TIMEOUT_5MIN)
        yield vm


def _update_vm_efi_spec(vm, spec=None, wait_for_interfaces=True):
    ResourceEditor(
        {
            vm: {
                "spec": {
                    "template": {
                        "spec": {
                            "domain": {"firmware": {"bootloader": {"efi": spec or {}}}}
                        }
                    }
                }
            }
        }
    ).update()
    restart_vm_wait_for_running_vm(vm=vm, wait_for_interfaces=wait_for_interfaces)


@pytest.mark.parametrize(
    "data_volume_scope_class",
    [
        pytest.param(
            {
                "dv_name": "dv-rhel-efi-secureboot-withdv",
                "image": RHEL_EFI_IMG,
                "storage_class": py_config["default_storage_class"],
                "dv_size": Images.Rhel.DEFAULT_DV_SIZE,
            }
        ),
    ],
    indirect=True,
)
class TestEFISecureBootRHEL:
    """
    Test EFI secureBoot VM with RHEL Images in DV.
    """

    @pytest.mark.order(before="test_efi_secureboot_is_default")
    @pytest.mark.polarion("CNV-1791")
    def test_secureboot_efi(self, data_volume_scope_class, rhel_efi_secureboot_vm):
        """
        Test VM boots with efi secureboot and check vm_xml values
        """
        assert_vm_xml_efi(vm=rhel_efi_secureboot_vm)
        validate_linux_efi(vm=rhel_efi_secureboot_vm)

    @pytest.mark.order(before="test_efi_secureboot_is_default")
    @pytest.mark.polarion("CNV-1789")
    def test_efi_secureboot_vm_cpu_and_memory(
        self, data_volume_scope_class, rhel_efi_secureboot_vm
    ):
        """
        Test EFI secureBoot VM cpu and memory values specified in spec match
        """
        run_ssh_commands(
            host=rhel_efi_secureboot_vm.ssh_exec,
            commands=[
                [
                    "sudo",
                    "dmidecode",
                    "-t",
                    "17",
                    "|",
                    "awk",
                    "\"'/Size/{print $2,$3}'\"",
                    "|",
                    "grep",
                    f"{VM_MEMORY} GB",
                ],
                shlex.split(f"nproc | grep {VM_CPU}"),
            ],
        )

    @pytest.mark.polarion("CNV-1790")
    def test_efi_secureboot_is_default(
        self, data_volume_scope_class, rhel_efi_secureboot_vm
    ):
        """
        Test VM with EFI is set as secureBoot by default.
        """
        _update_vm_efi_spec(vm=rhel_efi_secureboot_vm)
        assert_vm_xml_efi(vm=rhel_efi_secureboot_vm)
        validate_linux_efi(vm=rhel_efi_secureboot_vm)

    @pytest.mark.polarion("CNV-6951")
    def test_efi_secureboot_disabled(self, rhel_efi_secureboot_vm):
        """
        Test VM with EFI and disabled secureBoot.
        """
        _update_vm_efi_spec(vm=rhel_efi_secureboot_vm, spec={"secureBoot": False})
        assert_vm_xml_efi(vm=rhel_efi_secureboot_vm, secure_boot_enabled=False)
        validate_linux_efi(vm=rhel_efi_secureboot_vm)


@pytest.mark.polarion("CNV-4465")
def test_efi_secureboot_with_smm_disabled(namespace, unprivileged_client):
    """Test that EFI secureBoot VM with SMM disabled, does not get created"""
    with pytest.raises(UnprocessibleEntityError):
        with cluster_resource(VirtualMachineForTests)(
            name="efi-secureboot-smm-disabled-vm",
            namespace=namespace.name,
            image="kubevirt/microlivecd-container-disk-demo",
            client=unprivileged_client,
            smm_enabled=False,
            efi_params={"secureBoot": True},
        ):
            pytest.fail(
                "VM created with EFI SecureBoot enabled. SecureBoot requires SMM, which is currently disabled"
            )


@pytest.mark.parametrize(
    "golden_image_data_volume_scope_class",
    [
        pytest.param(
            {
                "dv_name": "dv-windows-efi-secureboot",
                "image": WIN_EFI_IMG,
                "storage_class": py_config["default_storage_class"],
                "dv_size": Images.Windows.DEFAULT_DV_SIZE,
            },
        ),
    ],
    indirect=True,
)
class TestEFISecureBootWindows:
    """
    Test EFI secureBoot VM with Windows Images in DV.
    """

    @pytest.mark.polarion("CNV-5464")
    def test_secureboot_efi(self, windows_efi_secureboot_vm):
        """
        Test VM boots with efi secureboot and check vm_xml values
        """
        assert_vm_xml_efi(vm=windows_efi_secureboot_vm)
        assert_windows_efi(vm=windows_efi_secureboot_vm)

    @pytest.mark.polarion("CNV-5465")
    def test_migrate_vm_windows(
        self, skip_access_mode_rwo_scope_class, windows_efi_secureboot_vm
    ):
        """Test EFI Windows VM is migrated."""

        migrate_vm_and_verify(
            vm=windows_efi_secureboot_vm,
            wait_for_interfaces=False,
            check_ssh_connectivity=True,
        )
        assert_vm_xml_efi(vm=windows_efi_secureboot_vm)
        assert_windows_efi(vm=windows_efi_secureboot_vm)

    @pytest.mark.polarion("CNV-6950")
    def test_efi_secureboot_disabled(self, windows_efi_secureboot_vm):
        """
        Test VM with EFI and disabled secureBoot.
        """
        _update_vm_efi_spec(
            vm=windows_efi_secureboot_vm,
            spec={"secureBoot": False},
            wait_for_interfaces=False,  # TODO: remove wait_for_interfaces=False when Windows EFI image is updated
        )
        assert_vm_xml_efi(vm=windows_efi_secureboot_vm, secure_boot_enabled=False)
        assert_windows_efi(vm=windows_efi_secureboot_vm)
