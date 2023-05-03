import logging
import os

import pytest
from ocp_resources.migration_policy import MigrationPolicy
from ocp_utilities.infra import cluster_resource
from pytest_testconfig import config as py_config

from tests.compute.virt.constants import STRESS_CPU_MEM_IO_COMMAND
from tests.compute.virt.utils import (
    get_stress_ng_pid,
    start_stress_on_vm,
    verify_stress_ng_pid_not_changed,
)
from tests.os_params import (
    FEDORA_LATEST,
    FEDORA_LATEST_LABELS,
    FEDORA_LATEST_OS,
    WINDOWS_10_TEMPLATE_LABELS,
)
from utilities.constants import TIMEOUT_20MIN, Images
from utilities.virt import migrate_vm_and_verify


LOGGER = logging.getLogger(__name__)

pytestmark = pytest.mark.usefixtures("skip_when_one_node")


@pytest.fixture(scope="class")
def migration_policy_with_allow_auto_converge(namespace):
    with cluster_resource(MigrationPolicy)(
        name="migration-policy-auto-converge",
        namespace_selector={"kubernetes.io/metadata.name": namespace.name},
        allow_auto_converge=True,
    ):
        yield


@pytest.fixture()
def cpu_mem_io_stress_started(vm_with_memory_load):
    start_stress_on_vm(
        vm=vm_with_memory_load,
        stress_command=STRESS_CPU_MEM_IO_COMMAND.format(
            workers="2", memory="50%", timeout="30m"
        ),
    )


@pytest.fixture()
def stress_pid_before_migration(vm_with_memory_load, cpu_mem_io_stress_started):
    return get_stress_ng_pid(
        ssh_exec=vm_with_memory_load.ssh_exec,
        windows="windows" in vm_with_memory_load.name,
    )


@pytest.fixture()
def migrate_vm_with_memory_load(vm_with_memory_load):
    migrate_vm_and_verify(
        vm=vm_with_memory_load, check_ssh_connectivity=True, timeout=TIMEOUT_20MIN
    )


@pytest.mark.usefixtures("migration_policy_with_allow_auto_converge")
class TestMigrationVMWithMemoryLoad:
    @pytest.mark.parametrize(
        "golden_image_data_volume_scope_function, vm_with_memory_load",
        [
            pytest.param(
                {
                    "dv_name": FEDORA_LATEST_OS,
                    "image": FEDORA_LATEST["image_path"],
                    "dv_size": FEDORA_LATEST["dv_size"],
                    "storage_class": py_config["default_storage_class"],
                },
                {
                    "vm_name": "fedora-vm-with-memory-load",
                    "template_labels": FEDORA_LATEST_LABELS,
                    "memory_requests": "4Gi",
                    "cpu_cores": 2,
                },
                marks=pytest.mark.polarion("CNV-4661"),
            ),
        ],
        indirect=True,
    )
    def test_fedora_vm_migrate_with_memory_load(
        self,
        vm_with_memory_load,
        stress_pid_before_migration,
        migrate_vm_with_memory_load,
    ):
        verify_stress_ng_pid_not_changed(
            vm=vm_with_memory_load, initial_pid=stress_pid_before_migration
        )

    @pytest.mark.ibm_bare_metal
    @pytest.mark.parametrize(
        "golden_image_data_volume_scope_function, vm_with_memory_load",
        [
            pytest.param(
                {
                    "dv_name": "dv-win10-wsl2",
                    "image": os.path.join(
                        Images.Windows.DIR, Images.Windows.WIM10_WSL2_IMG
                    ),
                    "dv_size": Images.Windows.WSL2_DV_SIZE,
                    "storage_class": py_config["default_storage_class"],
                },
                {
                    "vm_name": "windows-vm-with-memory-load",
                    "template_labels": WINDOWS_10_TEMPLATE_LABELS,
                    "memory_requests": Images.Windows.DEFAULT_MEMORY_SIZE_WSL,
                    "cpu_cores": 16,
                    "cpu_threads": 1,
                },
                marks=pytest.mark.polarion("CNV-9844"),
            ),
        ],
        indirect=True,
    )
    def test_windows_vm_migrate_with_memory_load(
        self,
        skip_if_workers_vms,
        vm_with_memory_load,
        stress_pid_before_migration,
        migrate_vm_with_memory_load,
    ):
        verify_stress_ng_pid_not_changed(
            vm=vm_with_memory_load,
            initial_pid=stress_pid_before_migration,
            windows=True,
        )
