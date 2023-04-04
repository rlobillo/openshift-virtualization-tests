"""
Run VM for 21 days and check that memory usage of system processes on the pod still below the limit
"""
import shlex
import time

import bitmath
import pytest
from ocp_utilities.infra import cluster_resource
from ocp_utilities.utils import run_ssh_commands

from tests.compute.virt.utils import get_stress_ng_pid, verify_stress_ng_pid_not_changed
from utilities.constants import TIMEOUT_12HRS
from utilities.virt import LOGGER, VirtualMachineForTests, fedora_vm_body, running_vm


pytestmark = [pytest.mark.longevity]


virt_process_memory_limits = {
    "virt-launcher-monitor": bitmath.MiB(25),
    "virt-launcher": bitmath.MiB(100),
    "libvirtd": bitmath.MiB(33),
    "virtlogd": bitmath.MiB(18),
}

TOTAL_DAYS = 21


def get_pod_process_memory_usage(pod, process_name):
    return bitmath.KiB(
        value=int(
            pod.execute(
                command=shlex.split(
                    f"bash -c 'ps -o rss --no-headers -p $(pidof {process_name})'"
                ),
                container="compute",
            )
        )
    )


def verify_memory_overuse(pod):
    memory_overuse = {}
    for process in virt_process_memory_limits.keys():
        memory_usage = get_pod_process_memory_usage(pod=pod, process_name=process)
        if memory_usage > virt_process_memory_limits[process]:
            memory_overuse[process] = {
                "memory usage": memory_usage,
                "memory limit": virt_process_memory_limits[process],
            }
    return memory_overuse


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
    LOGGER.info("Running memory load in VM")
    command = "nohup sudo stress-ng --vm 1 --vm-bytes 100% --vm-method all --verify -t 0 &>1 &"
    run_ssh_commands(host=vm_longevity.ssh_exec, commands=shlex.split(command))


@pytest.fixture()
def initial_stress_ng_pid(vm_longevity):
    return get_stress_ng_pid(ssh_exec=vm_longevity.ssh_exec)


@pytest.fixture()
def initial_memory_overuse(vm_longevity):
    LOGGER.info("Verifying initial memory usage")
    return verify_memory_overuse(pod=vm_longevity.vmi.virt_launcher_pod)


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
        current_memory_overuse = verify_memory_overuse(
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
