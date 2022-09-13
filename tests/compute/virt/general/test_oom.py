"""
Test VM with memory requests/limits and guest memory for OOM.
"""

import logging
import shlex
from contextlib import contextmanager
from multiprocessing import Process

import pytest
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from ocp_utilities.utils import run_ssh_commands

from utilities.constants import TIMEOUT_15MIN
from utilities.infra import cluster_resource
from utilities.virt import VirtualMachineForTests, fedora_vm_body, running_vm


pytestmark = pytest.mark.tier3

LOGGER = logging.getLogger(__name__)


@pytest.fixture()
def oom_vm(namespace, unprivileged_client):
    name = "oom-vm"
    with cluster_resource(VirtualMachineForTests)(
        name=name,
        namespace=namespace.name,
        body=fedora_vm_body(name=name),
        client=unprivileged_client,
        running=True,
        cpu_cores=2,
        cpu_requests="2",
        cpu_limits="2",
    ) as vm:
        running_vm(vm=vm)
        yield vm


def start_vm_stress(vm):
    commands = shlex.split(
        "nohup stress-ng --vm 1 --vm-bytes 100% --vm-method all --verify -t 15m -v --hdd 1 --io 1 &"
    )
    run_ssh_commands(host=vm.ssh_exec, commands=commands)


@contextmanager
def start_file_transfer(vm_ssh):
    file_name = "oom-test.txt"

    def _transfer_loop():
        while True:
            vm_ssh.fs.put(path_src=file_name, path_dst=file_name)

    run_ssh_commands(
        host=vm_ssh,
        commands=["dd", "if=/dev/zero", f"of={file_name}", "bs=100M", "count=1"],
    )

    transfer = Process(target=_transfer_loop)
    transfer.start()

    try:
        yield
    finally:
        transfer.terminate()
        run_ssh_commands(host=vm_ssh, commands=["rm", "-f", file_name])


def wait_vm_oom(vm):
    LOGGER.info(f"Monitoring VM {vm.name} under stress for 15 min")
    virt_launcher_pod = vm.vmi.virt_launcher_pod
    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_15MIN, sleep=1, func=lambda: virt_launcher_pod.status
    )
    try:
        for sample in samples:
            if sample == virt_launcher_pod.Status.FAILED:
                return
    except TimeoutExpiredError:
        return True


@pytest.mark.polarion("CNV-5321")
def test_vm_oom(oom_vm):
    start_vm_stress(vm=oom_vm)
    with start_file_transfer(vm_ssh=oom_vm.ssh_exec):
        assert wait_vm_oom(vm=oom_vm), "VM crashed"
