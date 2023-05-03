"""
Run VM for 21 days and check that memory usage of system processes on the pod still below the limit
"""
import time

import pytest
from ocp_utilities.infra import cluster_resource

from tests.compute.utils import get_virt_launcher_processes_memory_overuse
from tests.compute.virt.constants import STRESS_CPU_MEM_IO_COMMAND
from tests.compute.virt.utils import (
    get_stress_ng_pid,
    start_stress_on_vm,
    verify_stress_ng_pid_not_changed,
)
from utilities.constants import TIMEOUT_12HRS
from utilities.virt import LOGGER, VirtualMachineForTests, fedora_vm_body, running_vm


pytestmark = [pytest.mark.longevity]


TOTAL_DAYS = 21


@pytest.fixture()
def vm_longevity(unprivileged_client, namespace):
    name = "vm-longevity"
    with cluster_resource(VirtualMachineForTests)(
        client=unprivileged_client,
        name=name,
        namespace=namespace.name,
        body=fedora_vm_body(name=name),
        cpu_cores=2,
        memory_requests="2048Mi",
    ) as vm:
        running_vm(vm=vm)
        yield vm


@pytest.fixture()
def start_stress_ng(vm_longevity):
    start_stress_on_vm(
        vm=vm_longevity,
        stress_command=STRESS_CPU_MEM_IO_COMMAND.format(
            workers="1", memory="100%", timeout="0"
        ),
    )


@pytest.fixture()
def initial_stress_ng_pid(vm_longevity):
    return get_stress_ng_pid(ssh_exec=vm_longevity.ssh_exec)


@pytest.fixture()
def initial_memory_overuse(vm_longevity):
    LOGGER.info("Verifying initial memory usage")
    return get_virt_launcher_processes_memory_overuse(
        pod=vm_longevity.vmi.virt_launcher_pod
    )


@pytest.mark.polarion("CNV-4684")
def test_longevity_vm_run(
    vm_longevity, start_stress_ng, initial_stress_ng_pid, initial_memory_overuse
):
    processes_exceed_memory_limit = {}
    if initial_memory_overuse:
        LOGGER.error(f"Initial memory overuse: {initial_memory_overuse}")
        processes_exceed_memory_limit["Initial"] = initial_memory_overuse

    sleep_hrs = TIMEOUT_12HRS // 3600
    for iteration in range(TOTAL_DAYS * 2):
        current_iteration = iteration + 1
        LOGGER.info(f"Sleeping for {sleep_hrs} hours")
        time.sleep(TIMEOUT_12HRS)
        LOGGER.info(f"Iteration #{current_iteration}")

        LOGGER.info("stress-ng PID check")
        verify_stress_ng_pid_not_changed(
            vm=vm_longevity, initial_pid=initial_stress_ng_pid
        )

        LOGGER.info("Check memory usage on the pod")
        current_memory_overuse = get_virt_launcher_processes_memory_overuse(
            pod=vm_longevity.vmi.virt_launcher_pod
        )
        if current_memory_overuse:
            LOGGER.error(f"Memory overuse: {current_memory_overuse}")
            processes_exceed_memory_limit[
                f"{current_iteration * sleep_hrs}hrs"
            ] = current_memory_overuse

    assert (
        not processes_exceed_memory_limit
    ), f"Some processes on virt-launcher pod exceed the memory limit: {processes_exceed_memory_limit}"
