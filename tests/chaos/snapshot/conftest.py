import pytest
from ocp_utilities.infra import cluster_resource

from tests.chaos.snapshot.utils import VirtualMachineSnapshotWithDeadline
from utilities.constants import OS_FLAVOR_CIRROS, TIMEOUT_8MIN, Images
from utilities.storage import create_cirros_dv_for_snapshot
from utilities.virt import VirtualMachineForTests, running_vm


@pytest.fixture()
def chaos_snapshot_dv(
    chaos_namespace, storage_class_matrix_snapshot_matrix__function__
):
    """
    Define a DV that resides on OCS for use by a VM
    """
    yield create_cirros_dv_for_snapshot(
        name="chaos",
        namespace=chaos_namespace.name,
        storage_class=[*storage_class_matrix_snapshot_matrix__function__][0],
    )


@pytest.fixture()
def chaos_snapshot_vm(admin_client, chaos_namespace, chaos_snapshot_dv):
    dv_dict = chaos_snapshot_dv.to_dict()
    with cluster_resource(VirtualMachineForTests)(
        client=admin_client,
        name="vm-chaos-snapshot",
        namespace=chaos_namespace.name,
        os_flavor=OS_FLAVOR_CIRROS,
        memory_requests=Images.Cirros.DEFAULT_MEMORY_SIZE,
        data_volume_template={"metadata": dv_dict["metadata"], "spec": dv_dict["spec"]},
    ) as vm:
        running_vm(vm=vm, wait_for_interfaces=False, check_ssh_connectivity=False)
        yield vm


@pytest.fixture()
def chaos_online_snapshots(
    request,
    admin_client,
    chaos_snapshot_vm,
):
    vm_snapshots = []
    for idx in range(request.param["number_of_snapshots"]):
        with cluster_resource(VirtualMachineSnapshotWithDeadline)(
            name=f"snapshot-{chaos_snapshot_vm.name}-{idx}",
            namespace=chaos_snapshot_vm.namespace,
            vm_name=chaos_snapshot_vm.name,
            client=admin_client,
            teardown=False,
            failure_deadline=TIMEOUT_8MIN,
        ) as vm_snapshot:
            vm_snapshots.append(vm_snapshot)
            vm_snapshot.wait_snapshot_done(timeout=TIMEOUT_8MIN)
    yield vm_snapshots
