"""
VM to VM connectivity via secondary (bridged) interfaces.
"""
from collections import OrderedDict

import pytest

from tests.network.utils import assert_no_ping
from utilities.constants import IPV6_STR
from utilities.infra import cluster_resource, name_prefix
from utilities.network import (
    assert_ping_successful,
    compose_cloud_init_data_dict,
    get_ip_from_vm_or_virt_handler_pod,
    get_vmi_ip_v4_by_name,
    network_device,
    network_nad,
)
from utilities.virt import VirtualMachineForTests, fedora_vm_body, running_vm


pytestmark = pytest.mark.usefixtures(
    "skip_if_no_multinic_nodes", "hyperconverged_ovs_annotations_enabled_scope_session"
)


@pytest.fixture(scope="module")
def ovs_linux_bridge_device_name(index_number):
    yield f"br{next(index_number)}test"


def _masquerade_vmib_ip(vmb, bridge, ipv6_testing):
    # Using masquerade we can just ping vmb pods ip
    masquerade_interface = [
        i
        for i in vmb.vmi.instance.spec.domain.devices.interfaces
        if i["name"] == bridge and "masquerade" in i.keys()
    ]
    if masquerade_interface:
        if ipv6_testing:
            return get_ip_from_vm_or_virt_handler_pod(family=IPV6_STR, vm=vmb)
        return vmb.vmi.virt_launcher_pod.instance.status.podIP

    return get_vmi_ip_v4_by_name(vm=vmb, name=bridge)


@pytest.fixture(scope="class")
def ovs_linux_bridge_device_worker_1(
    bridge_device_matrix__class__,
    nodes_available_nics,
    worker_node1,
    ovs_linux_bridge_device_name,
):
    with network_device(
        interface_type=bridge_device_matrix__class__,
        nncp_name=f"ovs-linux-bridge-{name_prefix(worker_node1.name)}",
        interface_name=ovs_linux_bridge_device_name,
        node_selector=worker_node1.hostname,
        ports=[nodes_available_nics[worker_node1.name][-1]],
    ) as br:
        yield br


@pytest.fixture(scope="class")
def ovs_linux_bridge_device_worker_2(
    bridge_device_matrix__class__,
    nodes_available_nics,
    worker_node2,
    ovs_linux_bridge_device_name,
):
    with network_device(
        interface_type=bridge_device_matrix__class__,
        nncp_name=f"ovs-linux-bridge-{name_prefix(worker_node2.name)}",
        interface_name=ovs_linux_bridge_device_name,
        node_selector=worker_node2.hostname,
        ports=[nodes_available_nics[worker_node2.name][-1]],
    ) as br:
        yield br


@pytest.fixture(scope="class")
def ovs_linux_nad(
    bridge_device_matrix__class__,
    namespace,
    ovs_linux_bridge_device_worker_1,
    ovs_linux_bridge_device_worker_2,
    ovs_linux_bridge_device_name,
):
    with network_nad(
        namespace=namespace,
        nad_type=bridge_device_matrix__class__,
        nad_name=f"{ovs_linux_bridge_device_name}-nad",
        interface_name=ovs_linux_bridge_device_name,
    ) as nad:
        yield nad


@pytest.fixture(scope="class")
def ovs_linux_vlan1(vlan_index_number):
    return next(vlan_index_number)


@pytest.fixture(scope="class")
def ovs_linux_vlan2(vlan_index_number):
    return next(vlan_index_number)


@pytest.fixture(scope="class")
def ovs_linux_vlan3(vlan_index_number):
    return next(vlan_index_number)


@pytest.fixture(scope="class")
def ovs_linux_br1vlan1_nad(
    bridge_device_matrix__class__,
    namespace,
    ovs_linux_bridge_device_worker_1,
    ovs_linux_bridge_device_worker_2,
    ovs_linux_bridge_device_name,
    ovs_linux_vlan1,
):
    with network_nad(
        namespace=namespace,
        nad_type=bridge_device_matrix__class__,
        nad_name=f"{ovs_linux_bridge_device_name}-vlan{ovs_linux_vlan1}-nad",
        interface_name=ovs_linux_bridge_device_name,
        vlan=ovs_linux_vlan1,
    ) as nad:
        yield nad


@pytest.fixture(scope="class")
def ovs_linux_br1vlan2_nad(
    bridge_device_matrix__class__,
    namespace,
    ovs_linux_bridge_device_worker_1,
    ovs_linux_bridge_device_worker_2,
    ovs_linux_bridge_device_name,
    ovs_linux_vlan2,
):
    with network_nad(
        namespace=namespace,
        nad_type=bridge_device_matrix__class__,
        nad_name=f"{ovs_linux_bridge_device_name}-vlan{ovs_linux_vlan2}-nad",
        interface_name=ovs_linux_bridge_device_name,
        vlan=ovs_linux_vlan2,
    ) as nad:
        yield nad


@pytest.fixture(scope="class")
def ovs_linux_br1vlan3_nad(
    bridge_device_matrix__class__,
    namespace,
    ovs_linux_bridge_device_worker_1,
    ovs_linux_bridge_device_worker_2,
    ovs_linux_bridge_device_name,
    ovs_linux_vlan3,
):
    with network_nad(
        namespace=namespace,
        nad_type=bridge_device_matrix__class__,
        nad_name=f"{ovs_linux_bridge_device_name}-vlan{ovs_linux_vlan3}-nad",
        interface_name=ovs_linux_bridge_device_name,
        vlan=ovs_linux_vlan3,
    ) as nad:
        yield nad


def compose_cloud_init_data(dual_stack_nd, end_ip_octet):
    cloud_init_data_dict = {
        "ethernets": {
            "eth1": {"addresses": [f"10.200.0.{end_ip_octet}/24"]},
            "eth2": {"addresses": [f"10.200.1.{end_ip_octet}/24"]},
            "eth3": {"addresses": [f"10.200.2.{end_ip_octet}/24"]},
        }
    }

    return compose_cloud_init_data_dict(
        network_data=cloud_init_data_dict,
        ipv6_network_data=dual_stack_nd,
    )


@pytest.fixture(scope="class")
def ovs_linux_bridge_attached_vma(
    worker_node1,
    namespace,
    unprivileged_client,
    ovs_linux_nad,
    ovs_linux_br1vlan1_nad,
    ovs_linux_br1vlan2_nad,
    dual_stack_network_data,
):
    name = "vma"
    networks = OrderedDict()
    networks[ovs_linux_nad.name] = ovs_linux_nad.name
    networks[ovs_linux_br1vlan1_nad.name] = ovs_linux_br1vlan1_nad.name
    networks[ovs_linux_br1vlan2_nad.name] = ovs_linux_br1vlan2_nad.name

    cloud_init_data = compose_cloud_init_data(
        dual_stack_nd=dual_stack_network_data, end_ip_octet=1
    )

    with cluster_resource(VirtualMachineForTests)(
        namespace=namespace.name,
        name=name,
        body=fedora_vm_body(name=name),
        networks=networks,
        interfaces=networks.keys(),
        node_selector=worker_node1.hostname,
        cloud_init_data=cloud_init_data,
        client=unprivileged_client,
    ) as vm:
        vm.start(wait=True)
        yield vm


@pytest.fixture(scope="class")
def ovs_linux_bridge_attached_vmb(
    worker_node2,
    namespace,
    unprivileged_client,
    ovs_linux_nad,
    ovs_linux_br1vlan1_nad,
    ovs_linux_br1vlan3_nad,
    dual_stack_network_data,
):
    name = "vmb"
    networks = OrderedDict()
    networks[ovs_linux_nad.name] = ovs_linux_nad.name
    networks[ovs_linux_br1vlan1_nad.name] = ovs_linux_br1vlan1_nad.name
    networks[ovs_linux_br1vlan3_nad.name] = ovs_linux_br1vlan3_nad.name

    cloud_init_data = compose_cloud_init_data(
        dual_stack_nd=dual_stack_network_data, end_ip_octet=2
    )

    with cluster_resource(VirtualMachineForTests)(
        namespace=namespace.name,
        name=name,
        body=fedora_vm_body(name=name),
        networks=networks,
        interfaces=networks.keys(),
        node_selector=worker_node2.hostname,
        cloud_init_data=cloud_init_data,
        client=unprivileged_client,
    ) as vm:
        vm.start(wait=True)
        yield vm


@pytest.fixture(scope="class")
def ovs_linux_bridge_attached_running_vma(ovs_linux_bridge_attached_vma):
    return running_vm(vm=ovs_linux_bridge_attached_vma)


@pytest.fixture(scope="class")
def ovs_linux_bridge_attached_running_vmb(ovs_linux_bridge_attached_vmb):
    return running_vm(vm=ovs_linux_bridge_attached_vmb)


@pytest.mark.usefixtures("skip_when_one_node", "skip_ipv6_if_not_dual_stack_cluster")
class TestConnectivity:
    @pytest.mark.post_upgrade
    @pytest.mark.parametrize(
        "bridge",
        [
            pytest.param(
                "default",
                marks=(pytest.mark.polarion("CNV-2350")),
                id="Connectivity_between_VM_to_VM_over_POD_network_make_sure_it_works_while_L2_networks_exists",
            ),
            pytest.param(
                # this can be anything but default, right name should be indicated from 'ovs_linux_bridge_device_name'
                "l2_bridge_nad",
                marks=(pytest.mark.polarion("CNV-2080")),
                id="Connectivity_between_VM_to_VM_over_L2_bridge_network",
            ),
        ],
    )
    def test_bridge(
        self,
        bridge,
        ip_stack_version_matrix__module__,
        ovs_linux_nad,
        namespace,
        ovs_linux_bridge_attached_vma,
        ovs_linux_bridge_attached_vmb,
        ovs_linux_bridge_attached_running_vma,
        ovs_linux_bridge_attached_running_vmb,
    ):
        bridge = "default" if bridge == "default" else ovs_linux_nad.name
        ipv6_testing = ip_stack_version_matrix__module__ == IPV6_STR
        if ipv6_testing and bridge != "default":
            pytest.skip(
                msg="IPv6 is only supported on default interface, and shouldn't be covered in this test."
            )

        assert_ping_successful(
            src_vm=ovs_linux_bridge_attached_running_vma,
            dst_ip=_masquerade_vmib_ip(
                vmb=ovs_linux_bridge_attached_running_vmb,
                bridge=bridge,
                ipv6_testing=ipv6_testing,
            ),
        )

    @pytest.mark.post_upgrade
    @pytest.mark.polarion("CNV-2072")
    def test_positive_vlan(
        self,
        skip_if_workers_vms,
        namespace,
        ovs_linux_br1vlan1_nad,
        ovs_linux_bridge_attached_vma,
        ovs_linux_bridge_attached_vmb,
        ovs_linux_bridge_attached_running_vma,
        ovs_linux_bridge_attached_running_vmb,
    ):
        assert_ping_successful(
            src_vm=ovs_linux_bridge_attached_running_vma,
            dst_ip=get_vmi_ip_v4_by_name(
                vm=ovs_linux_bridge_attached_running_vmb,
                name=ovs_linux_br1vlan1_nad.name,
            ),
        )

    @pytest.mark.polarion("CNV-2075")
    def test_negative_vlan(
        self,
        skip_if_workers_vms,
        namespace,
        ovs_linux_br1vlan3_nad,
        ovs_linux_bridge_attached_vma,
        ovs_linux_bridge_attached_vmb,
        ovs_linux_bridge_attached_running_vma,
        ovs_linux_bridge_attached_running_vmb,
    ):
        assert_no_ping(
            src_vm=ovs_linux_bridge_attached_running_vma,
            dst_ip=get_vmi_ip_v4_by_name(
                vm=ovs_linux_bridge_attached_running_vmb,
                name=ovs_linux_br1vlan3_nad.name,
            ),
        )
