import pytest
from ocp_resources.virtual_machine_restore import VirtualMachineRestore

from tests.chaos.constants import CHAOS_ENGINE_NAME, LITMUS_NAMESPACE, ExperimentNames
from utilities.constants import TIMEOUT_2MIN, TIMEOUT_3MIN


pytestmark = pytest.mark.usefixtures("skip_if_no_storage_class_for_snapshot")


@pytest.mark.parametrize(
    "chaos_engine_from_yaml, chaos_online_snapshots",
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
                    {"name": "TOTAL_CHAOS_DURATION", "value": str(TIMEOUT_3MIN)},
                    {"name": "CHAOS_NAMESPACE", "value": LITMUS_NAMESPACE},
                    {"name": "CHAOSENGINE", "value": CHAOS_ENGINE_NAME},
                    {"name": "CHAOS_INTERVAL", "value": "1"},
                    {"name": "PODS_AFFECTED_PERC", "value": "67"},
                ],
            },
            {"number_of_snapshots": 3},
            marks=pytest.mark.polarion("CNV-8260"),
            id="openshift-apiserver",
        ),
        pytest.param(
            {
                "experiment_name": ExperimentNames.POD_DELETE,
                "app_info": {
                    "namespace": "openshift-cluster-storage-operator",
                    "label": "app=csi-snapshot-controller",
                    "kind": "deployment",
                },
                "components": [
                    {"name": "FORCE", "value": "true"},
                    {"name": "TOTAL_CHAOS_DURATION", "value": str(TIMEOUT_2MIN)},
                    {"name": "CHAOS_NAMESPACE", "value": LITMUS_NAMESPACE},
                    {"name": "CHAOSENGINE", "value": CHAOS_ENGINE_NAME},
                    {"name": "CHAOS_INTERVAL", "value": "30"},
                ],
            },
            {"number_of_snapshots": 3},
            marks=pytest.mark.polarion("CNV-8382"),
            id="snapshot-controller",
        ),
        pytest.param(
            {
                "experiment_name": ExperimentNames.POD_DELETE,
                "app_info": {
                    "namespace": "openshift-cnv",
                    "label": "kubevirt.io=virt-api",
                    "kind": "deployment",
                },
                "components": [
                    {"name": "FORCE", "value": "true"},
                    {"name": "TOTAL_CHAOS_DURATION", "value": str(TIMEOUT_2MIN)},
                    {"name": "CHAOS_NAMESPACE", "value": LITMUS_NAMESPACE},
                    {"name": "CHAOSENGINE", "value": CHAOS_ENGINE_NAME},
                    {"name": "CHAOS_INTERVAL", "value": "30"},
                ],
            },
            {"number_of_snapshots": 3},
            marks=pytest.mark.polarion("CNV-8534"),
            id="cnv-control-plane-virt-api",
        ),
        pytest.param(
            {
                "experiment_name": ExperimentNames.POD_DELETE,
                "app_info": {
                    "namespace": "openshift-storage",
                    "label": "app=csi-rbdplugin",
                    "kind": "daemonset",
                },
                "components": [
                    {"name": "FORCE", "value": "true"},
                    {"name": "TOTAL_CHAOS_DURATION", "value": str(TIMEOUT_2MIN)},
                    {"name": "CHAOS_NAMESPACE", "value": LITMUS_NAMESPACE},
                    {"name": "CHAOSENGINE", "value": CHAOS_ENGINE_NAME},
                    {"name": "CHAOS_INTERVAL", "value": "30"},
                ],
            },
            {"number_of_snapshots": 3},
            marks=pytest.mark.polarion("CNV-8750"),
            id="csi-driver",
        ),
    ],
    indirect=True,
)
@pytest.mark.chaos
def test_pod_delete_snapshot(
    admin_client,
    chaos_snapshot_vm,
    running_chaos_engine,
    krkn_process,
    chaos_online_snapshots,
):
    """
    This experiment tests the robustness of the VM snapshot feature
    by killing random function supported pods in their corresponding namespace
    and asserting that VM snapshots can be taken, restored and deleted during the process.
    """
    chaos_snapshot_vm.stop(wait=True)
    for idx, snapshot in enumerate(chaos_online_snapshots):
        with VirtualMachineRestore(
            name=f"restore-snapshot-{idx}",
            namespace=chaos_snapshot_vm.namespace,
            vm_name=chaos_snapshot_vm.name,
            snapshot_name=snapshot.name,
        ) as vm_restore:
            vm_restore.wait_restore_done()
        snapshot.clean_up()
    assert krkn_process.wait(), "Krkn process finished with errors."
