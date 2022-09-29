import pytest

from utilities.constants import TIMEOUT_5MIN, TIMEOUT_5SEC, Images
from utilities.infra import cluster_resource
from utilities.virt import VirtualMachineForTests, running_vm


@pytest.mark.parametrize(
    "chaos_vms_list_rhel9, pod_deleting_process",
    [
        pytest.param(
            {
                "number_of_vms": 3,
            },
            {
                "kind": "deployment",
                "pod_prefix": "apiserver",
                "namespace_name": "openshift-apiserver",
                "ratio": 0.5,
                "interval": TIMEOUT_5SEC,
                "max_duration": TIMEOUT_5MIN,
            },
        )
    ],
    indirect=True,
)
@pytest.mark.polarion("CNV-5428")
@pytest.mark.chaos
def test_pod_delete_openshift_apiserver(pod_deleting_process, chaos_vms_list_rhel9):
    """
    Verifies that VMs can be created, started, stopped and deleted
    while openshift-apiserver pods are continuously being deleted.
    """
    for vm in chaos_vms_list_rhel9:
        vm.deploy()
        running_vm(vm=vm, wait_for_interfaces=False, check_ssh_connectivity=False)


@pytest.mark.parametrize(
    "rebooted_master_node",
    [
        pytest.param(
            {"master_node_to_reboot": "node_without_kmp_manager"},
            id="nodes_without_kmp_manager",
            marks=pytest.mark.polarion("CNV-9293"),
        ),
        pytest.param(
            {"master_node_to_reboot": "node_with_kmp_manager"},
            id="node_with_kmp_manager",
            marks=(pytest.mark.polarion("CNV-5430"), pytest.mark.bugzilla("2130604")),
        ),
    ],
    indirect=True,
)
@pytest.mark.chaos
def test_master_node_restart(admin_client, chaos_namespace, rebooting_master_node):
    """
    This test verifies that a RHEL VM can be created, started, stopped and deleted
    while a given master node (randomly selected either from the nodes that have
    kubemacpool-mac-controller-manager pod or from the nodes that don't have it) is rebooted.
    """
    with cluster_resource(VirtualMachineForTests)(
        client=admin_client,
        name="vm-chaos",
        namespace=chaos_namespace.name,
        image=Images.Rhel.RHEL9_REGISTRY_GUEST_IMG,
        memory_requests=Images.Rhel.DEFAULT_MEMORY_SIZE,
    ) as vm:
        running_vm(vm=vm, wait_for_interfaces=False, check_ssh_connectivity=False)
