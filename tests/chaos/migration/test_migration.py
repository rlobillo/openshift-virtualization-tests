import pytest
from ocp_resources.virtual_machine_instance import VirtualMachineInstance

from utilities.constants import TIMEOUT_5MIN, TIMEOUT_5SEC


@pytest.mark.parametrize(
    "pod_deleting_process",
    [
        pytest.param(
            {
                "pod_prefix": "apiserver",
                "kind": "deployment",
                "namespace_name": "openshift-apiserver",
                "ratio": 0.5,
                "interval": TIMEOUT_5SEC,
                "max_duration": TIMEOUT_5MIN,
            },
        )
    ],
    indirect=True,
)
@pytest.mark.chaos
@pytest.mark.polarion("CNV-5455")
def test_pod_delete_openshift_apiserver_migration(
    chaos_vm_rhel9,
    pod_deleting_process,
    tainted_node_for_vm_migration,
):
    """
    This experiment tests the robustness of the cluster
    by killing a random apiserver pod in the `openshift-apiserver` namespace
    while a VM is being migrated and asserting that a given running VMI
    instance is still running before and after the test completes
    """

    assert (
        chaos_vm_rhel9.vmi.status == VirtualMachineInstance.Status.RUNNING
    ), "VirtualMachineInstance not running after chaos."
