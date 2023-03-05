"""
vGPU VM
"""
import pytest

from tests.compute.virt.gpu.utils import wait_for_manager_pods_deployed
from utilities.constants import (
    MDEV_GRID_T4_16Q_NAME,
    MDEV_GRID_T4_16Q_TYPE,
    MDEV_NAME,
    MDEV_TYPE,
    NVIDIA_VGPU_MANAGER_DS,
    VGPU_DEVICE_NAME,
    VGPU_GRID_T4_16Q_NAME,
)
from utilities.hco import ResourceEditorValidateHCOReconcile, wait_for_hco_conditions
from utilities.infra import ExecCommandOnPod, label_nodes


@pytest.fixture(scope="session")
def gpu_nodes_labeled_with_vm_vgpu(gpu_nodes):
    yield from label_nodes(
        nodes=gpu_nodes, labels={"nvidia.com/gpu.workload.config": "vm-vgpu"}
    )


@pytest.fixture(scope="session")
def vgpu_ready_nodes(admin_client, gpu_nodes_labeled_with_vm_vgpu):
    wait_for_manager_pods_deployed(
        admin_client=admin_client,
        ds_name=NVIDIA_VGPU_MANAGER_DS,
        gpu_nodes_amount=len(gpu_nodes_labeled_with_vm_vgpu),
    )
    yield gpu_nodes_labeled_with_vm_vgpu


@pytest.fixture(scope="session")
def non_existent_mdev_bus_nodes(workers_utility_pods, vgpu_ready_nodes):
    """
    Check if the mdev_bus needed for vGPU is availble.

    On the Worker Node on which GPU Device exists, Check if the
    mdev_bus needed for vGPU is availble.
    If it's not available, this means the simple-kmod-driver-container
    Pod might not be in running state in nvidia-driver namespace.
    """
    desired_bus = "mdev_bus"
    non_existent_mdev_bus_nodes = []
    for node in vgpu_ready_nodes:
        pod_exec = ExecCommandOnPod(utility_pods=workers_utility_pods, node=node)
        if desired_bus not in pod_exec.exec(
            command=f"ls /sys/class | grep {desired_bus} || true"
        ):
            non_existent_mdev_bus_nodes.append(node.name)
    if non_existent_mdev_bus_nodes:
        pytest.fail(
            msg=(
                f"On these nodes: {non_existent_mdev_bus_nodes} {desired_bus} is not available."
                "Ensure that in 'nvidia-driver' namespace simple-kmod-driver-container Pod is Running."
            )
        )


@pytest.fixture(scope="class")
def hco_cr_with_mdev_permitted_hostdevices(
    admin_client, hco_namespace, hyperconverged_resource_scope_class
):
    with ResourceEditorValidateHCOReconcile(
        patches={
            hyperconverged_resource_scope_class: {
                "spec": {
                    "mediatedDevicesConfiguration": {
                        "mediatedDevicesTypes": [MDEV_TYPE]
                    },
                    "permittedHostDevices": {
                        "mediatedDevices": [
                            {
                                "mdevNameSelector": MDEV_NAME,
                                "resourceName": VGPU_DEVICE_NAME,
                            }
                        ]
                    },
                }
            }
        },
    ):
        wait_for_hco_conditions(
            admin_client=admin_client,
            hco_namespace=hco_namespace,
        )
        yield


@pytest.fixture(scope="class")
def hco_cr_with_node_specific_mdev_permitted_hostdevices(
    admin_client,
    hco_namespace,
    hyperconverged_resource_scope_class,
    gpu_nodes,
):
    with ResourceEditorValidateHCOReconcile(
        patches={
            hyperconverged_resource_scope_class: {
                "spec": {
                    "mediatedDevicesConfiguration": {
                        "mediatedDevicesTypes": [MDEV_TYPE],
                        "nodeMediatedDeviceTypes": [
                            {
                                "mediatedDevicesTypes": [MDEV_GRID_T4_16Q_TYPE],
                                "nodeSelector": {
                                    "kubernetes.io/hostname": [*gpu_nodes][1].name
                                },
                            }
                        ],
                    },
                    "permittedHostDevices": {
                        "mediatedDevices": [
                            {
                                "mdevNameSelector": MDEV_NAME,
                                "resourceName": VGPU_DEVICE_NAME,
                            },
                            {
                                "mdevNameSelector": MDEV_GRID_T4_16Q_NAME,
                                "resourceName": VGPU_GRID_T4_16Q_NAME,
                            },
                        ]
                    },
                }
            }
        },
    ):
        wait_for_hco_conditions(
            admin_client=admin_client,
            hco_namespace=hco_namespace,
        )
        yield
