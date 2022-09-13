# -*- coding: utf-8 -*-

"""
Common templates test Fedora OS support
"""

import logging
import shlex

import pytest
from ocp_utilities.utils import run_ssh_commands

from tests.compute.ssp.supported_os.common_templates import (
    utils as common_templates_utils,
)
from tests.compute.utils import (
    validate_libvirt_persistent_domain,
    validate_pause_optional_migrate_unpause_linux_vm,
)
from utilities import console
from utilities.infra import is_bug_open
from utilities.virt import migrate_vm_and_verify, running_vm, wait_for_console


LOGGER = logging.getLogger(__name__)
TESTS_CLASS_NAME = "TestCommonTemplatesFedora"


HYPERV_DICT = {
    "spec": {
        "template": {
            "spec": {
                "domain": {
                    "clock": {
                        "utc": {},
                        "timer": {
                            "hpet": {"present": False},
                            "pit": {"tickPolicy": "delay"},
                            "rtc": {"tickPolicy": "catchup"},
                            "hyperv": {},
                        },
                    },
                    "features": {
                        "acpi": {},
                        "apic": {},
                        "hyperv": {
                            "relaxed": {},
                            "vapic": {},
                            "synictimer": {"direct": {}},
                            "vpindex": {},
                            "synic": {},
                            "spinlocks": {"spinlocks": 8191},
                            "frequencies": {},
                            "ipi": {},
                            "reenlightenment": {},
                            "reset": {},
                            "runtime": {},
                            "tlbflush": {},
                        },
                    },
                }
            }
        }
    }
}


@pytest.fixture()
def disabled_selinux(
    golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
):
    if is_bug_open(bug_id=1917024):
        selinux_enable_cmd = "sudo setenforce"
        run_ssh_commands(
            host=golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class.ssh_exec,
            commands=shlex.split(f"{selinux_enable_cmd} 0"),
        )
        yield
        run_ssh_commands(
            host=golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class.ssh_exec,
            commands=shlex.split(f"{selinux_enable_cmd} 1"),
        )
    else:
        yield


@pytest.mark.parametrize(
    "golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class",
    [
        (
            {
                "vm_dict": HYPERV_DICT,
            }
        )
    ],
    indirect=True,
)
class TestCommonTemplatesFedora:
    @pytest.mark.sno
    @pytest.mark.ibm_bare_metal
    @pytest.mark.ocp_interop
    @pytest.mark.dependency(name=f"{TESTS_CLASS_NAME}::create_vm")
    @pytest.mark.polarion("CNV-3351")
    def test_create_vm(
        self,
        skip_upstream,
        cluster_cpu_model_scope_class,
        unprivileged_client,
        namespace,
        fedora_os_matrix__class__,
        golden_image_data_volume_multi_fedora_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
    ):
        """Test CNV VM creation from template"""

        LOGGER.info("Create VM from template.")
        golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class.create(
            wait=True
        )

    @pytest.mark.sno
    @pytest.mark.ibm_bare_metal
    @pytest.mark.ocp_interop
    @pytest.mark.dependency(
        name=f"{TESTS_CLASS_NAME}::start_vm", depends=[f"{TESTS_CLASS_NAME}::create_vm"]
    )
    @pytest.mark.polarion("CNV-3345")
    def test_start_vm(
        self,
        skip_upstream,
        namespace,
        fedora_os_matrix__class__,
        golden_image_data_volume_multi_fedora_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
    ):
        """Test CNV common templates VM initiation"""

        running_vm(
            vm=golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class
        )

    @pytest.mark.sno
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::start_vm"])
    @pytest.mark.polarion("CNV-2651")
    def test_vm_hyperv(
        self,
        skip_upstream,
        namespace,
        fedora_os_matrix__class__,
        golden_image_data_volume_multi_fedora_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
    ):
        LOGGER.info("Verify VMI HyperV values.")
        common_templates_utils.check_vm_xml_hyperv(
            vm=golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class
        )
        common_templates_utils.check_vm_xml_clock(
            vm=golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class
        )

    @pytest.mark.sno
    @pytest.mark.ibm_bare_metal
    @pytest.mark.ocp_interop
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::start_vm"])
    @pytest.mark.polarion("CNV-3344")
    def test_vm_console(
        self,
        skip_upstream,
        namespace,
        fedora_os_matrix__class__,
        golden_image_data_volume_multi_fedora_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
    ):
        """Test CNV common templates VM console"""

        LOGGER.info("Verify VM console connection.")
        wait_for_console(
            vm=golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
            console_impl=console.Fedora,
        )

    @pytest.mark.sno
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::start_vm"])
    @pytest.mark.polarion("CNV-3348")
    def test_os_version(
        self,
        skip_upstream,
        namespace,
        fedora_os_matrix__class__,
        golden_image_data_volume_multi_fedora_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
    ):
        """Test CNV common templates OS version"""

        common_templates_utils.vm_os_version(
            vm=golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
        )

    @pytest.mark.sno
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::create_vm"])
    @pytest.mark.polarion("CNV-3347")
    def test_domain_label(
        self,
        skip_upstream,
        namespace,
        fedora_os_matrix__class__,
        golden_image_data_volume_multi_fedora_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
    ):
        """CNV common templates 'domain' label contains vm name"""
        vm = golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class
        domain_label = vm.instance.spec.template.metadata["labels"][
            "kubevirt.io/domain"
        ]
        assert domain_label == vm.name, f"Wrong domain label: {domain_label}"

    @pytest.mark.sno
    @pytest.mark.ibm_bare_metal
    @pytest.mark.ocp_interop
    @pytest.mark.dependency(
        name=f"{TESTS_CLASS_NAME}::vm_expose_ssh",
        depends=[f"{TESTS_CLASS_NAME}::start_vm"],
    )
    @pytest.mark.polarion("CNV-3349")
    def test_expose_ssh(
        self,
        skip_upstream,
        namespace,
        fedora_os_matrix__class__,
        golden_image_data_volume_multi_fedora_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
    ):
        """CNV common templates access VM via SSH"""

        assert golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class.ssh_exec.executor().is_connective(  # noqa: E501
            tcp_timeout=120
        ), "Failed to login via SSH"

    @pytest.mark.sno
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::vm_expose_ssh"])
    @pytest.mark.polarion("CNV-3937")
    def test_vmi_guest_agent_info(
        self,
        fedora_os_matrix__class__,
        golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
    ):
        """Test Guest OS agent info."""
        common_templates_utils.validate_os_info_vmi_vs_linux_os(
            vm=golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class
        )

    @pytest.mark.sno
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::vm_expose_ssh"])
    @pytest.mark.polarion("CNV-3573")
    def test_virtctl_guest_agent_os_info(
        self,
        fedora_os_matrix__class__,
        golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
    ):
        # TODO: remove restart_qemu_guest_agent_service when cnv moved to newer qemu versions
        common_templates_utils.restart_qemu_guest_agent_service(
            vm=golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
        )
        common_templates_utils.validate_os_info_virtctl_vs_linux_os(
            vm=golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class
        )

    @pytest.mark.sno
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::vm_expose_ssh"])
    @pytest.mark.polarion("CNV-3574")
    def test_virtctl_guest_agent_fs_info(
        self,
        fedora_os_matrix__class__,
        golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
        disabled_selinux,
    ):
        common_templates_utils.validate_fs_info_virtctl_vs_linux_os(
            vm=golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class
        )

    @pytest.mark.sno
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::vm_expose_ssh"])
    @pytest.mark.polarion("CNV-4549")
    def test_virtctl_guest_agent_user_info(
        self,
        fedora_os_matrix__class__,
        golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
    ):
        with console.Fedora(
            vm=golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class
        ):
            common_templates_utils.validate_user_info_virtctl_vs_linux_os(
                vm=golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class
            )

    @pytest.mark.sno
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::start_vm"])
    @pytest.mark.polarion("CNV-3668")
    def test_vm_machine_type(
        self,
        fedora_os_matrix__class__,
        skip_upstream,
        namespace,
        golden_image_data_volume_multi_fedora_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
    ):
        common_templates_utils.check_machine_type(
            vm=golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class
        )

    @pytest.mark.sno
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::start_vm"])
    @pytest.mark.polarion("CNV-5917")
    def test_pause_unpause_vm(
        self,
        skip_upstream,
        unprivileged_client,
        namespace,
        fedora_os_matrix__class__,
        golden_image_data_volume_multi_fedora_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
    ):
        validate_pause_optional_migrate_unpause_linux_vm(
            vm=golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
        )

    @pytest.mark.ibm_bare_metal
    @pytest.mark.ocp_interop
    @pytest.mark.polarion("CNV-5842")
    @pytest.mark.dependency(
        name=f"{TESTS_CLASS_NAME}::migrate_vm_and_verify",
        depends=[f"{TESTS_CLASS_NAME}::vm_expose_ssh"],
    )
    def test_migrate_vm(
        self,
        skip_upstream,
        skip_access_mode_rwo_scope_class,
        namespace,
        fedora_os_matrix__class__,
        golden_image_data_volume_multi_fedora_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
        ping_process_in_fedora_os,
    ):
        """Test SSH connectivity after migration"""
        migrate_vm_and_verify(
            vm=golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
            check_ssh_connectivity=True,
        )
        validate_libvirt_persistent_domain(
            vm=golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class
        )

    @pytest.mark.polarion("CNV-5901")
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::migrate_vm_and_verify"])
    def test_pause_unpause_after_migrate(
        self,
        skip_upstream,
        skip_access_mode_rwo_scope_class,
        namespace,
        fedora_os_matrix__class__,
        golden_image_data_volume_multi_fedora_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
        ping_process_in_fedora_os,
    ):
        validate_pause_optional_migrate_unpause_linux_vm(
            vm=golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
            pre_pause_pid=ping_process_in_fedora_os,
        )

    @pytest.mark.polarion("CNV-6006")
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::migrate_vm_and_verify"])
    def test_verify_virtctl_guest_agent_data_after_migrate(
        self,
        skip_upstream,
        namespace,
        fedora_os_matrix__class__,
        golden_image_data_volume_multi_fedora_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
    ):
        assert common_templates_utils.validate_virtctl_guest_agent_data_over_time(
            vm=golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class
        ), "Guest agent stopped responding"

    @pytest.mark.sno
    @pytest.mark.ibm_bare_metal
    @pytest.mark.ocp_interop
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::create_vm"])
    @pytest.mark.polarion("CNV-3346")
    def test_vm_deletion(
        self,
        skip_upstream,
        namespace,
        fedora_os_matrix__class__,
        golden_image_data_volume_multi_fedora_os_multi_storage_scope_class,
        golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
    ):
        """Test CNV common templates VM deletion"""
        golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class.delete(
            wait=True
        )
