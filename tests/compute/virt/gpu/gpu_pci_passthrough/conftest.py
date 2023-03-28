"""
GPU PCI Passthrough VM
"""


import pytest
from ocp_resources.resource import ResourceEditor

from tests.compute.virt.gpu.utils import get_gpu_nodes, wait_for_manager_pods_deployed
from utilities.constants import (
    GPU_DEVICE_ID,
    GPU_DEVICE_NAME,
    KERNEL_DRIVER,
    NVIDIA_VFIO_MANAGER_DS,
)
from utilities.hco import ResourceEditorValidateHCOReconcile, wait_for_hco_conditions
from utilities.infra import label_nodes


@pytest.fixture(scope="session")
def gpu_nodes_labeled_with_vm_passthrough(gpu_nodes):
    yield from label_nodes(
        nodes=gpu_nodes, labels={"nvidia.com/gpu.workload.config": "vm-passthrough"}
    )


@pytest.fixture(scope="session")
def gpu_passthrough_ready_nodes(admin_client, gpu_nodes_labeled_with_vm_passthrough):
    wait_for_manager_pods_deployed(
        admin_client=admin_client, ds_name=NVIDIA_VFIO_MANAGER_DS
    )
    yield gpu_nodes_labeled_with_vm_passthrough


@pytest.fixture(scope="session")
def fail_if_device_unbound_to_vfiopci_driver(
    workers_utility_pods, gpu_passthrough_ready_nodes
):
    """
    Fail if the Kernel Driver vfio-pci is not in use by the NVIDIA GPU Device.
    """
    device_unbound_nodes = []
    for node, lspci_out in get_gpu_nodes(
        util_pods=workers_utility_pods, nodes_list=gpu_passthrough_ready_nodes
    ).items():
        if KERNEL_DRIVER not in lspci_out:
            device_unbound_nodes.append(node.name)
    if device_unbound_nodes:
        pytest.fail(
            msg=(
                f"On these nodes: {device_unbound_nodes} GPU Devices are not bound to the {KERNEL_DRIVER} Driver."
                f"Ensure IOMMU and  {KERNEL_DRIVER} Machine Config is applied."
            )
        )


@pytest.fixture(scope="class")
def hco_cr_with_permitted_hostdevices(
    admin_client, hco_namespace, hyperconverged_resource_scope_class
):
    with ResourceEditorValidateHCOReconcile(
        patches={
            hyperconverged_resource_scope_class: {
                "spec": {
                    "permittedHostDevices": {
                        "pciHostDevices": [
                            {
                                "pciDeviceSelector": GPU_DEVICE_ID,
                                "resourceName": GPU_DEVICE_NAME,
                            }
                        ]
                    }
                }
            }
        },
    ):
        wait_for_hco_conditions(
            admin_client=admin_client,
            hco_namespace=hco_namespace,
        )
        yield


@pytest.fixture()
def updated_vm_gpus_spec(gpu_vma):
    vm_dict = gpu_vma.instance.to_dict()
    vm_spec_dict = vm_dict["spec"]["template"]["spec"]
    vm_spec_dict["domain"]["devices"].pop("hostDevices", "No key Found")
    ResourceEditor(patches={gpu_vma: vm_dict}, action="replace").update()
    ResourceEditor(
        patches={
            gpu_vma: {
                "spec": {
                    "template": {
                        "spec": {
                            "domain": {
                                "devices": {
                                    "gpus": [
                                        {
                                            "deviceName": GPU_DEVICE_NAME,
                                            "name": "gpus",
                                        }
                                    ]
                                }
                            }
                        }
                    }
                }
            }
        }
    ).update()
