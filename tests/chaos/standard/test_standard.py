import pytest
from ocp_resources.virtual_machine_instance import VirtualMachineInstance

from tests.chaos.constants import CHAOS_ENGINE_NAME, LITMUS_NAMESPACE, ExperimentNames
from utilities.constants import TIMEOUT_30SEC, Images
from utilities.infra import cluster_resource
from utilities.virt import VirtualMachineForTests, running_vm


@pytest.mark.parametrize(
    "chaos_engine_from_yaml",
    [
        pytest.param(
            {
                "experiment_name": ExperimentNames.POD_DELETE,
                "app_info": {
                    "namespace": "openshift-apiserver",
                    "label": "apiserver=true",
                    "kind": "deployment",
                },
                "components": [
                    {"name": "FORCE", "value": "true"},
                    {"name": "TOTAL_CHAOS_DURATION", "value": str(TIMEOUT_30SEC)},
                    {"name": "CHAOS_NAMESPACE", "value": LITMUS_NAMESPACE},
                    {"name": "CHAOSENGINE", "value": CHAOS_ENGINE_NAME},
                    {"name": "CHAOS_INTERVAL", "value": "1"},
                    {
                        "name": "PODS_AFFECTED_PERC",
                        "value": "67",
                    },  # Kill 2/3 of pods in the deployment
                ],
            },
        )
    ],
    indirect=True,
)
@pytest.mark.chaos
@pytest.mark.polarion("CNV-5428")
def test_pod_delete_openshift_apiserver(
    admin_client,
    vm_cirros_chaos,
    running_chaos_engine,
    krkn_process,
):
    """
    This experiment tests the robustness of the cluster
    by killing a random apiserver pod in the `openshift-apiserver` namespace
    and asserting that a given running VMI instance is still running before and after the test completes
    """
    assert krkn_process.wait(), "Krkn process finished with errors."
    assert (
        vm_cirros_chaos.vmi.status == VirtualMachineInstance.Status.RUNNING
    ), "VirtualMachineInstance not running after chaos."


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
