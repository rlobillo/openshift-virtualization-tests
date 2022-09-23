import pytest
from ocp_resources.virtual_machine_instance import VirtualMachineInstance

from tests.chaos.constants import CHAOS_ENGINE_NAME, LITMUS_NAMESPACE, ExperimentNames
from utilities.constants import TIMEOUT_30SEC


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
