"""
vGPU with Windows VM
"""
import logging
import os

import pytest
from ocp_resources.template import Template
from pytest_testconfig import config as py_config

from tests.compute.utils import validate_pause_optional_migrate_unpause_windows_vm
from tests.compute.virt.gpu.utils import (
    get_gpu_device_name_from_windows_vm,
    install_nvidia_drivers_on_windows_vm,
    restart_and_check_gpu_exists,
    verify_gpu_device_exists_in_vm,
)
from utilities.constants import NVIDIA_GRID_DRIVER_NAME, VGPU_DEVICE_NAME, Images
from utilities.virt import (
    VirtualMachineForTestsFromTemplate,
    get_windows_os_dict,
    running_vm,
)


pytestmark = [
    pytest.mark.post_upgrade,
    pytest.mark.tier3,
    pytest.mark.usefixtures("skip_if_no_gpu_node", "non_existent_mdev_bus_nodes"),
]


LOGGER = logging.getLogger(__name__)
WIN10 = get_windows_os_dict(windows_version="win-10")
WIN10_LABELS = WIN10["template_labels"]
DV_SIZE = Images.Windows.DEFAULT_DV_SIZE
TESTS_CLASS_NAME = "TestVGPUWindowsGPUSSpec"


@pytest.fixture(scope="class")
def gpu_vmc(
    unprivileged_client,
    namespace,
    golden_image_dv_scope_module_data_source_scope_class,
    gpu_vma,
):
    """
    VM Fixture for second VM for vGPU based Tests.
    """
    with VirtualMachineForTestsFromTemplate(
        name="win10-vgpu-gpus-spec-vm2",
        namespace=namespace.name,
        client=unprivileged_client,
        labels=Template.generate_template_labels(**WIN10_LABELS),
        data_source=golden_image_dv_scope_module_data_source_scope_class,
        node_selector=gpu_vma.node_selector,
        gpu_name=VGPU_DEVICE_NAME,
        cloned_dv_size=DV_SIZE,
    ) as vm:
        running_vm(vm=vm)
        install_nvidia_drivers_on_windows_vm(vm=vm)
        yield vm


@pytest.mark.parametrize(
    "golden_image_data_volume_scope_module, gpu_vma",
    [
        pytest.param(
            {
                "dv_name": WIN10_LABELS["os"],
                "image": os.path.join(Images.Windows.DIR, Images.Windows.WIN10_IMG),
                "storage_class": py_config["default_storage_class"],
                "dv_size": DV_SIZE,
            },
            {
                "vm_name": "win10-vgpu-gpus-spec-vm",
                "template_labels": WIN10_LABELS,
                "gpu_name": VGPU_DEVICE_NAME,
                "cloned_dv_size": DV_SIZE,
            },
            id="test_win10_vgpu",
        ),
    ],
    indirect=True,
)
@pytest.mark.usefixtures(
    "hco_cr_with_mdev_permitted_hostdevices",
)
class TestVGPUWindowsGPUSSpec:
    """
    Test vGPU with Windows VM using gpus spec.
    """

    @pytest.mark.dependency(name=f"{TESTS_CLASS_NAME}::test_access_vgpus_win_vm")
    @pytest.mark.polarion("CNV-8081")
    def test_access_vgpus_win_vm(self, gpu_vma):
        """
        Test vGPU is accessible in Windows VM with gpus spec.
        """
        verify_gpu_device_exists_in_vm(vm=gpu_vma)

    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::test_access_vgpus_win_vm"])
    @pytest.mark.polarion("CNV-8082")
    def test_pause_unpause_gpus_win_vm(self, gpu_vma):
        """
        Test Windows VM with vGPU using gpus spec, can be paused and unpaused successfully.
        """
        validate_pause_optional_migrate_unpause_windows_vm(vm=gpu_vma)

    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::test_access_vgpus_win_vm"])
    @pytest.mark.polarion("CNV-8083")
    def test_restart_gpus_win_vm(self, gpu_vma):
        """
        Test Windows VM with vGPU using gpus spec, can be restarted successfully.
        """
        restart_and_check_gpu_exists(vm=gpu_vma)

    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::test_access_vgpus_win_vm"])
    @pytest.mark.polarion("CNV-8573")
    def test_access_vgpus_in_both_win10_vm(self, gpu_vma, gpu_vmc):
        """
        Test vGPU is accessible in both the Windows10 VMs using same GPU, using GPUs spec.
        """
        vm_with_no_gpu = [
            vm.name
            for vm in [gpu_vma, gpu_vmc]
            if NVIDIA_GRID_DRIVER_NAME not in get_gpu_device_name_from_windows_vm(vm=vm)
        ]
        assert (
            not vm_with_no_gpu
        ), f"GPU does not exist in following vms: {vm_with_no_gpu}"
