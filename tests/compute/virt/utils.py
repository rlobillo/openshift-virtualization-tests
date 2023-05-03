import logging
import shlex
from contextlib import contextmanager

from ocp_resources.utils import TimeoutExpiredError
from ocp_utilities.utils import run_ssh_commands

from tests.compute.utils import (
    fetch_pid_from_linux_vm,
    kill_processes_by_name_linux,
    start_and_fetch_processid_on_linux_vm,
)
from utilities.hco import update_hco_annotations
from utilities.infra import is_jira_open
from utilities.virt import (
    migrate_vm_and_verify,
    verify_vm_migrated,
    wait_for_migration_finished,
    wait_for_updated_kv_value,
)


LOGGER = logging.getLogger(__name__)


class NodeMaintenanceException(Exception):
    def __init__(self, node, action, error):
        self.node = node
        self.action = action
        self.error = error

    def __str__(self):
        return f"{self.action} node maintenance failed: {self.node.name} - {self.error}"


@contextmanager
def running_sleep_in_linux(vm):
    process = "sleep"
    kill_processes_by_name_linux(vm=vm, process_name=process, check_rc=False)
    pid_orig = start_and_fetch_processid_on_linux_vm(
        vm=vm, process_name=process, args="1000", use_nohup=True
    )
    yield
    pid_after = fetch_pid_from_linux_vm(vm=vm, process_name=process)
    kill_processes_by_name_linux(vm=vm, process_name=process)
    assert pid_orig == pid_after, f"PID mismatch: {pid_orig} != {pid_after}"


@contextmanager
def append_feature_gate_to_hco(feature_gate, resource, client, namespace):
    with update_hco_annotations(
        resource=resource,
        path="developerConfiguration/featureGates",
        value=feature_gate,
    ):
        wait_for_updated_kv_value(
            admin_client=client,
            hco_namespace=namespace,
            path=[
                "developerConfiguration",
                "featureGates",
            ],
            value=feature_gate,
        )
        yield


def migrate_and_verify_multi_vms(vm_list):
    vms_dict = {}
    failed_migrations_list = []

    for vm in vm_list:
        vms_dict[vm.name] = {
            "node_before": vm.vmi.node,
            "vmi_source_pod": vm.vmi.virt_launcher_pod,
            "vm_mig": migrate_vm_and_verify(vm=vm, wait_for_migration_success=False),
        }

    for vm in vm_list:
        migration = vms_dict[vm.name]["vm_mig"]
        wait_for_migration_finished(vm=vm, migration=migration)
        migration.clean_up()

    for vm in vm_list:
        vm_sources = vms_dict[vm.name]
        try:
            verify_vm_migrated(
                vm=vm,
                node_before=vm_sources["node_before"],
                vmi_source_pod=vm_sources["vmi_source_pod"],
            )
        except (AssertionError, TimeoutExpiredError):
            failed_migrations_list.append(vm.name)

    assert (
        not failed_migrations_list
    ), f"Some VMs failed to migrate - {failed_migrations_list}"


def get_stress_ng_pid(ssh_exec, windows=False):
    stress = "stress-ng"
    LOGGER.info(f"Get pid of {stress}")
    command = (
        f'wsl sh -c \'ls -l /proc/*/exe | grep -m 1 {stress} | cut -d"/" -f3 | tr -d "\\n"\''
        if windows
        else f"pgrep {stress}"
    )
    return run_ssh_commands(
        host=ssh_exec,
        commands=shlex.split(command),
    )[0]


def verify_stress_ng_pid_not_changed(vm, initial_pid, windows=False):
    current_stress_ng_pid = get_stress_ng_pid(
        ssh_exec=vm.ssh_exec,
        windows=windows,
    )
    assert (
        initial_pid == current_stress_ng_pid
    ), f"stress-ng pid changed. Before: {initial_pid}. Current: {current_stress_ng_pid}"


def start_stress_on_vm(vm, stress_command):
    LOGGER.info(f"Running memory load in VM {vm.name}")
    if "windows" in vm.name:
        command = f"wsl nohup sh -c '{stress_command}'"
    else:
        command = stress_command
        if is_jira_open(jira_id="CNV-27477"):
            run_ssh_commands(
                host=vm.ssh_exec,
                commands=shlex.split("sudo dnf install -y stress-ng"),
            )
    run_ssh_commands(
        host=vm.ssh_exec,
        commands=shlex.split(command),
    )
