"""
GPU PCI Passthrough and vGPU Testing
"""
import pytest

from tests.compute.virt.gpu.utils import install_nvidia_drivers_on_windows_vm
from utilities.constants import GPU_DEVICE_ID, OS_FLAVOR_WINDOWS
from utilities.infra import ExecCommandOnPod
from utilities.virt import vm_instance_from_template


@pytest.fixture(scope="session")
def gpu_nodes(workers_utility_pods, schedulable_nodes):
    """
    Find GPU Worker Node, where GPU device is allocated.
    """
    nodes = {}
    for node in schedulable_nodes:
        pod_exec = ExecCommandOnPod(utility_pods=workers_utility_pods, node=node)
        out = pod_exec.exec(
            command="sudo /sbin/lspci -nnk | grep -A 3 '3D controller' || true"
        )
        if GPU_DEVICE_ID in out:
            nodes.update({node: out})
    return nodes


@pytest.fixture(scope="session")
def skip_if_no_gpu_node(gpu_nodes):
    if not gpu_nodes:
        pytest.skip("Only run on a Cluster with at-least one GPU Worker node")


@pytest.fixture(scope="session")
def skip_if_only_one_gpu_node(skip_if_no_gpu_node, gpu_nodes):
    if len(gpu_nodes) < 2:
        pytest.skip("Only run on a Cluster with at-least two GPU Worker nodes")


@pytest.fixture(scope="class")
def gpu_vma(
    request,
    unprivileged_client,
    namespace,
    golden_image_dv_scope_module_data_source_scope_class,
    gpu_nodes,
):
    """
    VM Fixture for both GPU Passthrough and vGPU based Tests.
    """
    with vm_instance_from_template(
        request=request,
        unprivileged_client=unprivileged_client,
        namespace=namespace,
        data_source=golden_image_dv_scope_module_data_source_scope_class,
        node_selector=[*gpu_nodes][0].name,
    ) as gpu_vm:
        if gpu_vm.os_flavor.startswith(OS_FLAVOR_WINDOWS):
            install_nvidia_drivers_on_windows_vm(vm=gpu_vm)
        yield gpu_vm
