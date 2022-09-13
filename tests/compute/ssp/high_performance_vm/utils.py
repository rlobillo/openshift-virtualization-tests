import logging
import re
import shlex

import xmltodict
from ocp_utilities.utils import run_ssh_commands

from utilities.infra import ExecCommandOnPod


LOGGER = logging.getLogger(__name__)


def get_vm_cpu_list(vm):
    vcpuinfo = vm.vmi.virt_launcher_pod.execute(
        command=shlex.split(f"virsh vcpuinfo {vm.namespace}_{vm.name}")
    )

    return [cpu.split()[1] for cpu in vcpuinfo.split("\n") if re.search(r"^CPU:", cpu)]


def get_numa_node_cpu_dict(vm):
    """
    Extract NUMA nodes from libvirt

    Args:
        vm (VirtualMachine): VM

    Returns:
        dict with numa id as key and cpu list as value.
        Example:
            {'<numa_node_id>': [cpu_list]}
    """
    out = vm.vmi.virt_launcher_pod.execute(command=shlex.split("virsh capabilities"))
    numa = xmltodict.parse(out)["capabilities"]["host"]["cache"]["bank"]

    return {elem["@id"]: elem["@cpus"].split(",") for elem in numa}


def get_numa_cpu_allocation(vm_cpus, numa_nodes):
    """
    Find NUMA node # where VM CPUs are allocated.
    """

    def _parse_ranges_to_list(ranges):
        cpus = []
        for elem in ranges:
            if "-" in elem:
                start, end = elem.split("-")
                cpus.extend([str(num) for num in range(int(start), int(end) + 1)])
            else:
                cpus.append(elem)
        return cpus

    for node in numa_nodes.keys():
        if all(
            cpu in _parse_ranges_to_list(ranges=numa_nodes[node]) for cpu in vm_cpus
        ):
            return node


def get_sriov_pci_address(vm):
    """
    Get PCI address of SRIOV device in virsh.

    Args:
        vm (VirtualMachine): VM object

    Returns:
        list: PCI address(es) of SRIOV device
        Example:
            ['0000:3b:0a.2']
    """
    sriov_pci_addresses = []
    hostdev_devices = vm.vmi.xml_dict["domain"]["devices"]["hostdev"]
    for device in hostdev_devices:
        addr = device["source"]["address"]
        sriov_pci_addresses.append(
            f'{addr["@domain"][2:]}:{addr["@bus"][2:]}:{addr["@slot"][2:]}.{addr["@function"][2:]}'
        )

    return sriov_pci_addresses


def get_numa_sriov_allocation(vm, utility_pods):
    """
    Find NUMA node number where SR-IOV device is allocated.
    """
    sriov_alocation_list = []
    sriov_addresses = get_sriov_pci_address(vm=vm)
    for address in sriov_addresses:
        sriov_alocation_list.append(
            ExecCommandOnPod(utility_pods=utility_pods, node=vm.vmi.node)
            .exec(command=f"cat /sys/bus/pci/devices/{address}/numa_node")
            .strip()
        )

    return sriov_alocation_list


def validate_dedicated_emulatorthread(vm):
    cpu = vm.instance.spec.template.spec.domain.cpu
    template_flavor_expected_cpu_count = cpu.threads * cpu.cores * cpu.sockets
    nproc_output = int(
        re.match(
            r"(\d+)",
            run_ssh_commands(
                host=vm.ssh_exec,
                commands=["nproc"],
            )[0],
        ).group(1)
    )
    assert (
        nproc_output == template_flavor_expected_cpu_count
    ), f"Guest CPU count {nproc_output} is not as expected, {template_flavor_expected_cpu_count}"
    LOGGER.info("Verify VM XML - Isolate Emulator Thread.")
    cputune = vm.vmi.xml_dict["domain"]["cputune"]
    emulatorpin_cpuset = cputune["emulatorpin"]["@cpuset"]
    if template_flavor_expected_cpu_count == 1:
        vcpupin_cpuset = cputune["vcpupin"]["@cpuset"]
        # When isolateEmulatorThread is set to True,
        # Ensure that KubeVirt will allocate one additional dedicated CPU,
        # exclusively for the emulator thread.
        assert emulatorpin_cpuset != vcpupin_cpuset, assert_msg(
            emulatorpin=emulatorpin_cpuset, vcpupin=vcpupin_cpuset
        )
    else:
        vcpupin_cpuset = [pcpu_id["@cpuset"] for pcpu_id in cputune["vcpupin"]]
        assert emulatorpin_cpuset not in vcpupin_cpuset, assert_msg(
            emulatorpin=emulatorpin_cpuset, vcpupin=vcpupin_cpuset
        )


def validate_iothreads_emulatorthread_on_same_pcpu(vm):
    LOGGER.info(f"Verify IO Thread Policy in VM {vm.name} domain XML.")
    cputune = vm.vmi.xml_dict["domain"]["cputune"]
    emulatorpin_cpuset = cputune["emulatorpin"]["@cpuset"]
    iothreadpin_cpuset = cputune["iothreadpin"]["@cpuset"]
    # When dedicatedCPUPlacement is True, isolateEmulatorThread is True,
    # dedicatedIOThread is True and ioThreadsPolicy is set "auto".
    # Ensure that KubeVirt will allocate ioThreads to the same
    # physical cpu of the QEMU Emulator Thread.
    assert iothreadpin_cpuset == emulatorpin_cpuset, (
        f"If isolateEmulatorThread=True and also ioThreadsPolicy is 'auto',"
        f"KubeVirt should allocate same physical cpu."
        f"Expected: iothreadspin cpuset {iothreadpin_cpuset} equals emulatorpin cpuset {emulatorpin_cpuset}."
    )


def assert_msg(emulatorpin, vcpupin):
    return (
        f"If isolateEmulatorThread=True, KubeVirt shouldn't allocate same pcpu "
        f"for both vcpupin {vcpupin} and emulatorpin {emulatorpin}"
    )


def assert_virt_launcher_pod_cpu_manager_node_selector(virt_launcher_pod):
    assert (
        virt_launcher_pod.spec.nodeSelector.cpumanager
    ), "NUMA Pod doesn't have cpumanager node selector"


def assert_numa_cpu_allocation(vm_cpus, numa_nodes):
    assert get_numa_cpu_allocation(
        vm_cpus=vm_cpus, numa_nodes=numa_nodes
    ), f"Not all vCPUs are pinned in one numa node! VM vCPUS {vm_cpus}, NUMA node CPU lists {numa_nodes}"


def assert_cpus_and_sriov_on_same_node(vm, utility_pods):
    cpu_alloc = get_numa_cpu_allocation(
        vm_cpus=get_vm_cpu_list(vm=vm),
        numa_nodes=get_numa_node_cpu_dict(vm=vm),
    )
    sriov_alloc = get_numa_sriov_allocation(vm=vm, utility_pods=utility_pods)

    assert set(cpu_alloc) == set(
        sriov_alloc
    ), f"SR-IOV and CPUs are on different NUMA nodes! CPUs allocated to node {cpu_alloc}, SR-IOV to node {sriov_alloc}"
