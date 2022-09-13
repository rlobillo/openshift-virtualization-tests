# -*- coding: utf-8 -*-

import logging
import shlex

import pytest
from ocp_utilities.utils import run_ssh_commands
from pytest_testconfig import config as py_config

from tests.compute.virt.utils import get_stress_ng_pid
from tests.os_params import FEDORA_LATEST
from utilities.constants import TIMEOUT_10MIN, TIMEOUT_30MIN
from utilities.infra import cluster_resource
from utilities.virt import VirtualMachineForTests, migrate_vm_and_verify, running_vm


LOGGER = logging.getLogger(__name__)


@pytest.fixture()
def vm_with_mem_load(
    cluster_cpu_model_scope_function,
    unprivileged_client,
    namespace,
    data_volume_scope_function,
):
    with cluster_resource(VirtualMachineForTests)(
        name="vm-with-mem-load",
        namespace=namespace.name,
        client=unprivileged_client,
        running=True,
        cpu_cores=2,
        cpu_requests="2",
        cpu_limits="2",
        memory_requests="4196Mi",
        data_volume=data_volume_scope_function,
    ) as vm:
        running_vm(vm=vm)
        yield vm


@pytest.fixture()
def start_vm_stress(vm_with_mem_load):
    # TODO: Increase the load with F33 (since F32 is bit flaky)
    LOGGER.info("Running memory load in VM")
    command = (
        f"nohup sudo stress-ng --vm 1 --vm-bytes 50% --vm-method all --verify -t {TIMEOUT_30MIN}s "
        "-v --hdd 1 --io 1 --vm-keep &> /dev/null &"
    )
    run_ssh_commands(host=vm_with_mem_load.ssh_exec, commands=shlex.split(command))


@pytest.fixture()
def vm_info_before_migrate(vm_with_mem_load):
    source_node = vm_with_mem_load.vmi.virt_launcher_pod.node
    stress_ng_pid_before = get_stress_ng_pid(ssh_exec=vm_with_mem_load.ssh_exec)
    return source_node, stress_ng_pid_before


@pytest.fixture()
def migrate_vm_with_memory_load(vm_info_before_migrate, vm_with_mem_load):
    migrate_vm_and_verify(vm=vm_with_mem_load, timeout=TIMEOUT_10MIN)


@pytest.mark.parametrize(
    "data_volume_scope_function",
    [
        pytest.param(
            {
                "dv_name": "dv-fedora-mem-load-vm",
                "image": FEDORA_LATEST["image_path"],
                "storage_class": py_config["default_storage_class"],
                "dv_size": FEDORA_LATEST["dv_size"],
            },
            marks=pytest.mark.polarion("CNV-4661"),
            id="case: migrate vm with memory load on the guest",
        ),
    ],
    indirect=True,
)
def test_vm_migrate_with_memory_load(
    skip_rwo_default_access_mode,
    data_volume_scope_function,
    vm_with_mem_load,
    start_vm_stress,
    vm_info_before_migrate,
    migrate_vm_with_memory_load,
):
    _, stress_ng_pid_before = vm_info_before_migrate
    stress_ng_pid_after = get_stress_ng_pid(ssh_exec=vm_with_mem_load.ssh_exec)
    assert (
        stress_ng_pid_before == stress_ng_pid_after
    ), "stress ng stopped or changed during migration"
