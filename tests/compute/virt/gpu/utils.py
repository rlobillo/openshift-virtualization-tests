import shlex

from ocp_utilities.utils import run_ssh_commands

from utilities.constants import (
    NVIDIA_GRID_DRIVER_NAME,
    OS_FLAVOR_WINDOWS,
    TIMEOUT_3MIN,
    VGPU_DEVICE_NAME,
)
from utilities.virt import restart_vm_wait_for_running_vm, running_vm


def get_num_gpu_devices_in_rhel_vm(vm):
    return int(
        run_ssh_commands(
            host=vm.ssh_exec,
            commands=[
                "bash",
                "-c",
                "/sbin/lspci -nnk | grep NVIDIA | grep Tesla | wc -l",
            ],
        )[0].strip()
    )


def get_gpu_device_name_from_windows_vm(vm):
    return run_ssh_commands(
        host=vm.ssh_exec,
        commands=[shlex.split("wmic path win32_VideoController get name")],
    )[0]


def verify_gpu_device_exists_in_vm(vm):
    gpu_device_name = fetch_gpu_device_name_from_vm_instance(vm=vm)
    if vm.os_flavor.startswith(OS_FLAVOR_WINDOWS):
        # NOTE: vGPU uses NVIDIA GRID Drivers and GPU Passthrough uses normal NVIDIA Drivers.
        nvidia_device = (
            NVIDIA_GRID_DRIVER_NAME
            if gpu_device_name == VGPU_DEVICE_NAME
            else "NVIDIA Tesla"
        )
        assert nvidia_device in get_gpu_device_name_from_windows_vm(
            vm=vm
        ), f"GPU device: {gpu_device_name} does not exist in the windows vm: {vm.name}."
    else:
        assert (
            get_num_gpu_devices_in_rhel_vm(vm=vm) == 1
        ), f"GPU device: {gpu_device_name} does not exist in rhel vm: {vm.name}."


def restart_and_check_gpu_exists(vm):
    restart_vm_wait_for_running_vm(vm=vm, ssh_timeout=TIMEOUT_3MIN)
    verify_gpu_device_exists_in_vm(vm=vm)


def verify_gpu_device_exists_on_node(gpu_nodes, device_name):
    device_exists_failed_checks = []
    for gpu_node in gpu_nodes:
        for status_type in ["allocatable", "capacity"]:
            resources = getattr(gpu_node.instance.status, status_type).keys()
            if device_name not in resources:
                device_exists_failed_checks.append(
                    {
                        gpu_node.name: {
                            f"device_{status_type}": {
                                "expected": device_name,
                                "actual": resources,
                            }
                        }
                    }
                )
    assert (
        not device_exists_failed_checks
    ), f"Failed checks: {device_exists_failed_checks}"


def verify_gpu_expected_count_updated_on_node(gpu_nodes, device_name, expected_count):
    device_expected_count_failed_checks = []
    for gpu_node in gpu_nodes:
        for status_type in ["allocatable", "capacity"]:
            resources = getattr(gpu_node.instance.status, status_type)
            if resources[device_name] != expected_count:
                device_expected_count_failed_checks.append(
                    {
                        gpu_node.name: {
                            f"device_{status_type}_count": {
                                "expected": expected_count,
                                "actual": resources[device_name],
                            }
                        }
                    }
                )
    assert (
        not device_expected_count_failed_checks
    ), f"Failed checks: {device_expected_count_failed_checks}"


def fetch_gpu_device_name_from_vm_instance(vm):
    devices = vm.vmi.instance.spec.domain.devices
    return (
        devices.gpus[0].deviceName
        if devices.get("gpus")
        else devices.hostDevices[0].deviceName
    )


def install_nvidia_drivers_on_windows_vm(vm):
    # Installs NVIDIA Drivers placed on the Windows-10 or win2k19 Images.
    # vGPU uses NVIDIA GRID Drivers and GPU Passthrough uses normal NVIDIA Drivers.
    gpu_mode = (
        "vgpu"
        if fetch_gpu_device_name_from_vm_instance(vm) == VGPU_DEVICE_NAME
        else "gpu"
    )
    run_ssh_commands(
        host=vm.ssh_exec,
        commands=[
            shlex.split(
                f"C:\\NVIDIA\\{gpu_mode}\\International\\setup.exe -s & exit /b 0",
                posix=False,
            )
        ],
    )
    # Wait for Running VM, as only vGPU VM Reboots after installing NVIDIA GRID Drivers.
    if fetch_gpu_device_name_from_vm_instance(vm=vm) == VGPU_DEVICE_NAME:
        running_vm(vm=vm)
