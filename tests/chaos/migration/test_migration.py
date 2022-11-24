import pytest
from ocp_resources.deployment import Deployment
from ocp_resources.virtual_machine_instance import VirtualMachineInstance

from tests.chaos.migration.utils import verify_vmi_migration
from utilities.constants import (
    TIMEOUT_2MIN,
    TIMEOUT_5MIN,
    TIMEOUT_5SEC,
    TIMEOUT_30SEC,
    NamespacesNames,
)


pytestmark = pytest.mark.usefixtures("chaos_namespace", "cluster_monitoring_process")


@pytest.mark.parametrize(
    "pod_deleting_process",
    [
        pytest.param(
            {
                "pod_prefix": "apiserver",
                "resource": Deployment,
                "namespace_name": NamespacesNames.OPENSHIFT_APISERVER,
                "ratio": 0.5,
                "interval": TIMEOUT_5SEC,
                "max_duration": TIMEOUT_5MIN,
            },
            marks=pytest.mark.polarion("CNV-5455"),
            id="openshift-apiserver",
        ),
        pytest.param(
            {
                "pod_prefix": "virt-launcher",
                "resource": VirtualMachineInstance,
                "namespace_name": NamespacesNames.CHAOS,
                "ratio": 1,
                "interval": TIMEOUT_30SEC,
                "max_duration": TIMEOUT_2MIN,
            },
            marks=pytest.mark.polarion("CNV-5454"),
            id="virt_launcher",
        ),
        pytest.param(
            {
                "pod_prefix": "rook-ceph-operator",
                "resource": Deployment,
                "namespace_name": NamespacesNames.OPENSHIFT_STORAGE,
                "ratio": 1,
                "interval": TIMEOUT_5SEC,
                "max_duration": TIMEOUT_5MIN,
            },
            marks=pytest.mark.polarion("CNV-7257"),
            id="rook-ceph-operator",
        ),
    ],
    indirect=True,
)
@pytest.mark.chaos
def test_pod_delete_migration(
    chaos_vm_rhel9,
    pod_deleting_process,
    tainted_node_for_vm_migration,
):
    """
    This experiment tests the robustness of the cluster
    by killing random function supported pods in their corresponding namespaces
    while a VM is being migrated and asserting that a given running VMI
    is running on a different node at the end of the test
    """

    assert verify_vmi_migration(
        vm=chaos_vm_rhel9,
        initial_node=tainted_node_for_vm_migration,
    ), "The VMI has not been migrated to a different node."
