import pytest
from ocp_resources.resource import Resource, ResourceEditor
from ocp_resources.utils import TimeoutSampler
from ocp_resources.virtual_machine_instance import VirtualMachineInstance
from ocp_resources.virtual_machine_instance_migration import (
    VirtualMachineInstanceMigration,
)

from tests.chaos.constants import CHAOS_ENGINE_NAME, LITMUS_NAMESPACE, ExperimentNames
from utilities.constants import TIMEOUT_1MIN, TIMEOUT_5SEC, TIMEOUT_30SEC
from utilities.virt import verify_vm_migrated, wait_for_migration_finished


def wait_for_migration_and_verify(dyn_client, vm, initial_node, initial_vmi_source_pod):
    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_1MIN,
        sleep=TIMEOUT_5SEC,
        func=lambda: list(
            VirtualMachineInstanceMigration.get(
                dyn_client=dyn_client, namespace=vm.namespace
            )
        ),
    )
    for sample in samples:
        if sample:
            if vm.vmi.name == sample[0].instance.spec.vmiName:
                migration = sample[0]
                break

    wait_for_migration_finished(vm=vm, migration=migration)
    verify_vm_migrated(
        vm=vm,
        node_before=initial_node,
        vmi_source_pod=initial_vmi_source_pod,
        wait_for_interfaces=False,
        check_ssh_connectivity=False,
    )


def taint_node_and_verify_migration(admin_client, vm):
    initial_node = vm.vmi.node
    initial_vmi_source_pod = vm.vmi.virt_launcher_pod
    with ResourceEditor(
        patches={
            initial_node: {
                "spec": {
                    "taints": [
                        {
                            "effect": "NoSchedule",
                            "key": f"{Resource.ApiGroup.KUBEVIRT_IO}/drain",
                            "value": "draining",
                        }
                    ]
                }
            }
        }
    ):
        wait_for_migration_and_verify(
            dyn_client=admin_client,
            vm=vm,
            initial_node=initial_node,
            initial_vmi_source_pod=initial_vmi_source_pod,
        )


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
@pytest.mark.polarion("CNV-5455")
def test_pod_delete_openshift_apiserver_migration(
    admin_client,
    vm_cirros_chaos,
    running_chaos_engine,
    krkn_process,
):
    """
    This experiment tests the robustness of the cluster
    by killing a random apiserver pod in the `openshift-apiserver` namespace
    while a VM is being migrated and asserting that a given running VMI
    instance is still running before and after the test completes
    """

    taint_node_and_verify_migration(admin_client=admin_client, vm=vm_cirros_chaos)
    assert krkn_process.wait(), "Krkn process finished with errors."
    assert (
        vm_cirros_chaos.vmi.status == VirtualMachineInstance.Status.RUNNING
    ), "VirtualMachineInstance not running after chaos."
