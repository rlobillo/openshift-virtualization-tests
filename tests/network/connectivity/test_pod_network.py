"""
VM to VM connectivity
"""

import pytest

from utilities.infra import cluster_resource
from utilities.network import (
    assert_ping_successful,
    compose_cloud_init_data_dict,
    get_ip_from_vm_or_virt_handler_pod,
)
from utilities.virt import VirtualMachineForTests, fedora_vm_body, running_vm


@pytest.fixture()
def pod_net_vma(
    skip_ipv6_if_not_dual_stack_cluster,
    worker_node1,
    namespace,
    unprivileged_client,
    nic_models_matrix__module__,
    cloud_init_ipv6_network_data,
):
    name = "vma"
    with cluster_resource(VirtualMachineForTests)(
        namespace=namespace.name,
        name=name,
        node_selector=worker_node1.hostname,
        client=unprivileged_client,
        network_model=nic_models_matrix__module__,
        body=fedora_vm_body(name=name),
        cloud_init_data=cloud_init_ipv6_network_data,
    ) as vm:
        vm.start(wait=True)
        yield vm


@pytest.fixture()
def pod_net_vmb(
    skip_ipv6_if_not_dual_stack_cluster,
    worker_node2,
    namespace,
    unprivileged_client,
    nic_models_matrix__module__,
    cloud_init_ipv6_network_data,
):
    name = "vmb"
    with cluster_resource(VirtualMachineForTests)(
        namespace=namespace.name,
        name=name,
        node_selector=worker_node2.hostname,
        client=unprivileged_client,
        network_model=nic_models_matrix__module__,
        body=fedora_vm_body(name=name),
        cloud_init_data=cloud_init_ipv6_network_data,
    ) as vm:
        vm.start(wait=True)
        yield vm


@pytest.fixture()
def pod_net_running_vma(pod_net_vma):
    return running_vm(vm=pod_net_vma, wait_for_cloud_init=True)


@pytest.fixture()
def pod_net_running_vmb(pod_net_vmb):
    return running_vm(vm=pod_net_vmb, wait_for_cloud_init=True)


@pytest.fixture(scope="module")
def cloud_init_ipv6_network_data(dual_stack_network_data):
    return compose_cloud_init_data_dict(ipv6_network_data=dual_stack_network_data)


@pytest.mark.polarion("CNV-2332")
def test_connectivity_over_pod_network(
    ip_stack_version_matrix__module__,
    skip_when_one_node,
    pod_net_vma,
    pod_net_vmb,
    pod_net_running_vma,
    pod_net_running_vmb,
    namespace,
):
    """
    Check connectivity
    """
    dst_ip = get_ip_from_vm_or_virt_handler_pod(
        family=ip_stack_version_matrix__module__, vm=pod_net_running_vmb
    )
    assert dst_ip, f"Cannot get valid IP address from {pod_net_running_vmb.vmi.name}."

    assert_ping_successful(
        src_vm=pod_net_running_vma,
        dst_ip=dst_ip,
    )
