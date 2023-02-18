from contextlib import contextmanager

from ocp_resources.datavolume import DataVolume
from ocp_resources.virtual_machine_snapshot import VirtualMachineSnapshot
from ocp_utilities.infra import cluster_resource

from utilities.constants import Images
from utilities.infra import get_http_image_url
from utilities.storage import write_file
from utilities.virt import VirtualMachineForTests


@contextmanager
def create_vm_for_snapshot_upgrade_tests(
    vm_name, namespace, client, storage_class_for_snapshot
):
    dv = DataVolume(
        name=f"dv-{vm_name}",
        namespace=namespace,
        source="http",
        url=get_http_image_url(
            image_directory=Images.Cirros.DIR, image_name=Images.Cirros.QCOW2_IMG
        ),
        storage_class=storage_class_for_snapshot,
        size=Images.Cirros.DEFAULT_DV_SIZE,
        api_name="storage",
    )
    dv.to_dict()
    with cluster_resource(VirtualMachineForTests)(
        client=client,
        name=f"vm-{vm_name}",
        namespace=dv.res["metadata"]["namespace"],
        memory_requests=Images.Cirros.DEFAULT_MEMORY_SIZE,
        data_volume_template={"metadata": dv.res["metadata"], "spec": dv.res["spec"]},
    ) as vm:
        write_file(
            vm=vm,
            filename="first-file.txt",
            content="first-file",
        )
        yield vm


@contextmanager
def create_snapshot_for_upgrade(vm, client):
    """Creating a snapshot of vm and adding a text file to the vm"""
    with cluster_resource(VirtualMachineSnapshot)(
        name=f"snapshot-{vm.name}",
        namespace=vm.namespace,
        vm_name=vm.name,
        client=client,
    ) as vm_snapshot:
        vm_snapshot.wait_snapshot_done()
        write_file(
            vm=vm,
            filename="second-file.txt",
            content="second-file",
        )
        yield vm_snapshot
