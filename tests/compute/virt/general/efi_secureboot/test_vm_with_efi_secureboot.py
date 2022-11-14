"""
EFI secureBoot VM
"""

import logging
import os

import pytest
from ocp_resources.template import Template
from openshift.dynamic.exceptions import UnprocessibleEntityError
from pytest_testconfig import config as py_config

from tests.compute.utils import (
    assert_vm_xml_efi,
    assert_windows_efi,
    update_vm_efi_spec_and_restart,
)
from utilities.constants import TIMEOUT_5MIN, Images
from utilities.infra import cluster_resource
from utilities.virt import (
    VirtualMachineForTests,
    VirtualMachineForTestsFromTemplate,
    migrate_vm_and_verify,
    running_vm,
)


LOGGER = logging.getLogger(__name__)


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
        cpu_cores=2,
        smm_enabled=True,
        efi_params={"secureBoot": True},
    ) as vm:
        # EFI Windows OS takes longer to be up and connective
        # TODO: remove wait_for_interfaces=False when Windows EFI image is updated
        running_vm(vm=vm, wait_for_interfaces=False, ssh_timeout=TIMEOUT_5MIN)
        yield vm


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
                "image": os.path.join(Images.Windows.DIR, Images.Windows.WIM10_EFI_IMG),
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
        update_vm_efi_spec_and_restart(
            vm=windows_efi_secureboot_vm,
            spec={"secureBoot": False},
            wait_for_interfaces=False,  # TODO: remove wait_for_interfaces=False when Windows EFI image is updated
        )
        assert_vm_xml_efi(vm=windows_efi_secureboot_vm, secure_boot_enabled=False)
        assert_windows_efi(vm=windows_efi_secureboot_vm)
