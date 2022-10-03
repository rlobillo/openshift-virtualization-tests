# -*- coding: utf-8 -*-

"""
Common templates test RHEL OS support
"""

import logging

import pytest

import tests.compute.ssp.utils as ssp_utils
from tests.compute.ssp.supported_os.common_templates import (
    utils as common_templates_utils,
)
from tests.compute.ssp.supported_os.utils import check_qemu_guest_agent_installed
from tests.compute.utils import (
    assert_linux_efi,
    assert_vm_xml_efi,
    validate_libvirt_persistent_domain,
    validate_pause_optional_migrate_unpause_linux_vm,
)
from utilities import console
from utilities.virt import migrate_vm_and_verify, running_vm, wait_for_console


pytestmark = pytest.mark.post_upgrade


LOGGER = logging.getLogger(__name__)
TESTS_CLASS_NAME = "TestCommonTemplatesRhel"


class TestCommonTemplatesRhel:
    @pytest.mark.sno
    @pytest.mark.smoke
    @pytest.mark.dependency(name=f"{TESTS_CLASS_NAME}::create_vm")
    @pytest.mark.polarion("CNV-3802")
    def test_create_vm(
        self,
        skip_upstream,
        cluster_cpu_model_scope_class,
        unprivileged_client,
        namespace,
        rhel_os_matrix__class__,
        golden_image_data_volume_multi_rhel_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
    ):
        """Test CNV VM creation from template"""

        LOGGER.info("Create VM from template.")
        golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class.create(
            wait=True
        )

    @pytest.mark.sno
    @pytest.mark.smoke
    @pytest.mark.dependency(
        name=f"{TESTS_CLASS_NAME}::start_vm", depends=[f"{TESTS_CLASS_NAME}::create_vm"]
    )
    @pytest.mark.polarion("CNV-3266")
    def test_start_vm(
        self,
        skip_upstream,
        unprivileged_client,
        namespace,
        rhel_os_matrix__class__,
        golden_image_data_volume_multi_rhel_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
    ):
        """Test CNV common templates VM initiation"""
        # RHEL6 does not have qemu guest agent installed
        guest_agent_support = "rhel-6" not in [*rhel_os_matrix__class__][0]

        running_vm(
            vm=golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
            wait_for_interfaces=guest_agent_support,
        )

    @pytest.mark.sno
    @pytest.mark.smoke
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::start_vm"])
    @pytest.mark.polarion("CNV-3259")
    def test_vm_console(
        self,
        skip_upstream,
        unprivileged_client,
        namespace,
        rhel_os_matrix__class__,
        golden_image_data_volume_multi_rhel_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
    ):
        """Test CNV common templates VM console"""

        LOGGER.info("Verify VM console connection.")
        wait_for_console(
            vm=golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
            console_impl=console.RHEL,
        )

    @pytest.mark.sno
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::start_vm"])
    @pytest.mark.polarion("CNV-3318")
    def test_os_version(
        self,
        skip_upstream,
        unprivileged_client,
        namespace,
        rhel_os_matrix__class__,
        golden_image_data_volume_multi_rhel_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
    ):
        """Test CNV common templates OS version"""

        common_templates_utils.vm_os_version(
            vm=golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
        )

    @pytest.mark.sno
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::start_vm"])
    @pytest.mark.polarion("CNV-8712")
    def test_efi_secureboot_enabled_by_default(
        self,
        skip_upstream,
        skip_if_os_version_below_rhel9,
        namespace,
        rhel_os_matrix__class__,
        golden_image_data_volume_multi_rhel_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
    ):
        """Test CNV common templates EFI secureboot status"""

        vm = (
            golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class
        )
        assert_vm_xml_efi(vm=vm)
        assert_linux_efi(vm=vm)

    @pytest.mark.sno
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::create_vm"])
    @pytest.mark.polarion("CNV-3306")
    def test_domain_label(
        self,
        skip_upstream,
        unprivileged_client,
        namespace,
        rhel_os_matrix__class__,
        golden_image_data_volume_multi_rhel_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
    ):
        """CNV common templates 'domain' label contains vm name"""

        label = golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class.instance.spec.template.metadata[  # noqa: E501
            "labels"
        ][
            "kubevirt.io/domain"
        ]
        assert (
            label
            == golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class.name
        ), f"Wrong domain label: {label}"

    @pytest.mark.sno
    @pytest.mark.smoke
    @pytest.mark.dependency(
        name=f"{TESTS_CLASS_NAME}::vm_expose_ssh",
        depends=[f"{TESTS_CLASS_NAME}::start_vm"],
    )
    @pytest.mark.polarion("CNV-3320")
    def test_expose_ssh(
        self,
        skip_upstream,
        unprivileged_client,
        namespace,
        rhel_os_matrix__class__,
        golden_image_data_volume_multi_rhel_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
    ):
        """CNV common templates access VM via SSH"""
        assert golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class.ssh_exec.executor().is_connective(  # noqa: E501
            tcp_timeout=120
        ), "Failed to login via SSH"

    @pytest.mark.sno
    @pytest.mark.smoke
    @pytest.mark.dependency(
        name=f"{TESTS_CLASS_NAME}::vmi_guest_agent",
        depends=[f"{TESTS_CLASS_NAME}::vm_expose_ssh"],
    )
    @pytest.mark.polarion("CNV-6688")
    def test_vmi_guest_agent_exists(
        self,
        skip_upstream,
        skip_guest_agent_on_rhel6,
        rhel_os_matrix__class__,
        golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
    ):
        assert check_qemu_guest_agent_installed(
            ssh_exec=golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class.ssh_exec
        ), "qemu guest agent package is not installed"

    @pytest.mark.sno
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::vmi_guest_agent"])
    @pytest.mark.polarion("CNV-3513")
    def test_vmi_guest_agent_info(
        self,
        rhel_os_matrix__class__,
        golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
    ):
        common_templates_utils.validate_os_info_vmi_vs_linux_os(
            vm=golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class
        )

    @pytest.mark.sno
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::vmi_guest_agent"])
    @pytest.mark.polarion("CNV-4195")
    def test_virtctl_guest_agent_os_info(
        self,
        rhel_os_matrix__class__,
        golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
    ):
        # TODO: remove restart_qemu_guest_agent_service when cnv moved to newer qemu versions
        common_templates_utils.restart_qemu_guest_agent_service(
            vm=golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
        )
        common_templates_utils.validate_os_info_virtctl_vs_linux_os(
            vm=golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class
        )

    @pytest.mark.sno
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::vmi_guest_agent"])
    @pytest.mark.polarion("CNV-4550")
    def test_virtctl_guest_agent_user_info(
        self,
        rhel_os_matrix__class__,
        golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
    ):
        with console.RHEL(
            vm=golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class
        ):
            common_templates_utils.validate_user_info_virtctl_vs_linux_os(
                vm=golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class
            )

    @pytest.mark.sno
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::vmi_guest_agent"])
    @pytest.mark.polarion("CNV-6531")
    def test_virtctl_guest_agent_fs_info(
        self,
        skip_guest_agent_on_rhel,
        rhel_os_matrix__class__,
        golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
    ):
        common_templates_utils.validate_fs_info_virtctl_vs_linux_os(
            vm=golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class
        )

    @pytest.mark.sno
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::start_vm"])
    @pytest.mark.polarion("CNV-3671")
    def test_vm_machine_type(
        self,
        skip_upstream,
        unprivileged_client,
        namespace,
        rhel_os_matrix__class__,
        golden_image_data_volume_multi_rhel_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
    ):
        common_templates_utils.check_machine_type(
            vm=golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class
        )

    @pytest.mark.sno
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::start_vm"])
    @pytest.mark.polarion("CNV-4201")
    def test_vm_smbios_default(
        self,
        skip_upstream,
        unprivileged_client,
        smbios_from_kubevirt_config,
        namespace,
        rhel_os_matrix__class__,
        golden_image_data_volume_multi_rhel_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
    ):
        ssp_utils.check_vm_xml_smbios(
            vm=golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
            cm_values=smbios_from_kubevirt_config,
        )

    @pytest.mark.sno
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::start_vm"])
    @pytest.mark.polarion("CNV-5916")
    def test_pause_unpause_vm(
        self,
        skip_upstream,
        unprivileged_client,
        namespace,
        rhel_os_matrix__class__,
        golden_image_data_volume_multi_rhel_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
    ):
        validate_pause_optional_migrate_unpause_linux_vm(
            vm=golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
        )

    @pytest.mark.smoke
    @pytest.mark.polarion("CNV-3038")
    @pytest.mark.dependency(
        name=f"{TESTS_CLASS_NAME}::migrate_vm_and_verify",
        depends=[f"{TESTS_CLASS_NAME}::vm_expose_ssh"],
    )
    def test_migrate_vm(
        self,
        skip_upstream,
        skip_access_mode_rwo_scope_class,
        unprivileged_client,
        namespace,
        rhel_os_matrix__class__,
        golden_image_data_volume_multi_rhel_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
        ping_process_in_rhel_os,
    ):
        """Test SSH connectivity after migration"""
        migrate_vm_and_verify(
            vm=golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
            check_ssh_connectivity=True,
        )
        validate_libvirt_persistent_domain(
            vm=golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class
        )

    @pytest.mark.polarion("CNV-5902")
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::migrate_vm_and_verify"])
    def test_pause_unpause_after_migrate(
        self,
        skip_upstream,
        skip_access_mode_rwo_scope_class,
        unprivileged_client,
        namespace,
        rhel_os_matrix__class__,
        golden_image_data_volume_multi_rhel_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
        ping_process_in_rhel_os,
    ):
        validate_pause_optional_migrate_unpause_linux_vm(
            vm=golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
            pre_pause_pid=ping_process_in_rhel_os,
        )

    @pytest.mark.polarion("CNV-6007")
    @pytest.mark.dependency(
        depends=[
            f"{TESTS_CLASS_NAME}::vmi_guest_agent",
            f"{TESTS_CLASS_NAME}::migrate_vm_and_verify",
        ]
    )
    def test_verify_virtctl_guest_agent_data_after_migrate(
        self,
        skip_upstream,
        namespace,
        rhel_os_matrix__class__,
        golden_image_data_volume_multi_rhel_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
    ):
        assert common_templates_utils.validate_virtctl_guest_agent_data_over_time(
            vm=golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class
        ), "Guest agent stopped responding"

    @pytest.mark.sno
    @pytest.mark.smoke
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::create_vm"])
    @pytest.mark.polarion("CNV-3269")
    def test_vm_deletion(
        self,
        skip_upstream,
        unprivileged_client,
        namespace,
        rhel_os_matrix__class__,
        golden_image_data_volume_multi_rhel_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
    ):
        """Test CNV common templates VM deletion"""
        golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class.delete(
            wait=True
        )
