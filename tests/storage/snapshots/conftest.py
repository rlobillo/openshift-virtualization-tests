# -*- coding: utf-8 -*-

"""
Pytest conftest file for CNV Storage snapshots tests
"""
import logging
import shlex

import pytest
from ocp_resources.role_binding import RoleBinding
from ocp_resources.virtual_machine_snapshot import VirtualMachineSnapshot
from ocp_utilities.utils import run_ssh_commands

from tests.storage.snapshots.constants import WINDOWS_DIRECTORY_PATH
from tests.storage.snapshots.utils import assert_directory_existence
from tests.storage.utils import create_cirros_vm, create_windows19_vm, set_permissions
from utilities.constants import TIMEOUT_10MIN, UNPRIVILEGED_USER
from utilities.infra import cluster_resource
from utilities.storage import create_cirros_dv_for_snapshot, write_file


LOGGER = logging.getLogger(__name__)


def check_snapshot_indication(snapshot, is_online):
    snapshot_indications = snapshot.instance.status.indications
    if is_online:
        assert "Online" in snapshot_indications
    else:
        assert not snapshot_indications


@pytest.fixture()
def cirros_dv_for_snapshot(
    namespace,
    cirros_vm_name,
    storage_class_matrix_snapshot_matrix__module__,
):
    yield create_cirros_dv_for_snapshot(
        name=cirros_vm_name,
        namespace=namespace.name,
        storage_class=[*storage_class_matrix_snapshot_matrix__module__][0],
    )


@pytest.fixture()
def cirros_vm_for_snapshot(
    admin_client,
    namespace,
    cirros_vm_name,
    cirros_dv_for_snapshot,
):
    """
    Create a VM with a DV from the cirros_dv fixture
    """
    with create_cirros_vm(
        admin_client=admin_client,
        cirros_dv=cirros_dv_for_snapshot,
        cirros_vm_name=cirros_vm_name,
    ) as vm:
        yield vm


@pytest.fixture()
def snapshots_with_content(
    request,
    namespace,
    admin_client,
    cirros_vm_for_snapshot,
):
    """
    Creates a requested number of snapshots with content
    The default behavior of the fixture is creating an offline
    snapshot unless {online_vm = True} declared in the test
    """
    vm_snapshots = []
    is_online_test = request.param.get("online_vm", False)
    for idx in range(request.param["number_of_snapshots"]):
        # write_file check if the vm is running and if not, start the vm
        # after the file have been written the function stops the vm
        write_file(
            vm=cirros_vm_for_snapshot,
            filename=f"before-snap-{idx+1}.txt",
            content=f"before-snap-{idx+1}",
        )
        if is_online_test:
            cirros_vm_for_snapshot.start(wait=True)
        with cluster_resource(VirtualMachineSnapshot)(
            name=f"snapshot-{cirros_vm_for_snapshot.name}-number-{idx + 1}",
            namespace=cirros_vm_for_snapshot.namespace,
            vm_name=cirros_vm_for_snapshot.name,
            client=admin_client,
            teardown=False,
        ) as vm_snapshot:
            vm_snapshots.append(vm_snapshot)
            vm_snapshot.wait_snapshot_done()
            write_file(
                vm=cirros_vm_for_snapshot,
                filename=f"after-snap-{idx+1}.txt",
                content=f"after-snap-{idx+1}",
            )
    check_snapshot_indication(snapshot=vm_snapshot, is_online=is_online_test)
    yield vm_snapshots

    for vm_snapshot in vm_snapshots:
        vm_snapshot.clean_up()


@pytest.fixture()
def permissions_for_dv(namespace):
    """
    Sets DV permissions for an unprivileged client
    """
    with set_permissions(
        role_name="datavolume-cluster-role",
        verbs=["*"],
        permissions_to_resources=["datavolumes", "datavolumes/source"],
        binding_name="role-bind-data-volume",
        namespace=namespace.name,
        subjects_kind="User",
        subjects_name=UNPRIVILEGED_USER,
        subjects_api_group=RoleBinding.api_group,
    ):
        yield


@pytest.fixture()
def windows_vm_for_snapshot(
    request,
    namespace,
    unprivileged_client,
    nodes_common_cpu_model,
    storage_class_matrix_snapshot_matrix__module__,
):
    with create_windows19_vm(
        dv_name=request.param["dv_name"],
        namespace=namespace.name,
        client=unprivileged_client,
        vm_name=request.param["vm_name"],
        cpu_model=nodes_common_cpu_model,
        storage_class=[*storage_class_matrix_snapshot_matrix__module__][0],
    ) as vm:
        yield vm


@pytest.fixture()
def snapshot_windows_directory(windows_vm_for_snapshot):
    cmd = shlex.split(
        f'powershell -command "New-Item -Path {WINDOWS_DIRECTORY_PATH} -ItemType Directory"',
    )
    run_ssh_commands(host=windows_vm_for_snapshot.ssh_exec, commands=cmd)
    assert_directory_existence(
        expected_result=True,
        windows_vm=windows_vm_for_snapshot,
        directory_path=WINDOWS_DIRECTORY_PATH,
    )


@pytest.fixture()
def windows_snapshot(
    snapshot_windows_directory,
    windows_vm_for_snapshot,
):
    with cluster_resource(VirtualMachineSnapshot)(
        name="windows-snapshot",
        namespace=windows_vm_for_snapshot.namespace,
        vm_name=windows_vm_for_snapshot.name,
    ) as snapshot:
        yield snapshot


@pytest.fixture()
def snapshot_dirctory_removed(windows_vm_for_snapshot, windows_snapshot):
    windows_snapshot.wait_ready_to_use(timeout=TIMEOUT_10MIN)
    cmd = shlex.split(
        f'powershell -command "Remove-Item -Path {WINDOWS_DIRECTORY_PATH} -Recurse"',
    )
    run_ssh_commands(host=windows_vm_for_snapshot.ssh_exec, commands=cmd)
    assert_directory_existence(
        expected_result=False,
        windows_vm=windows_vm_for_snapshot,
        directory_path=WINDOWS_DIRECTORY_PATH,
    )
    windows_vm_for_snapshot.stop(wait=True)


@pytest.fixture()
def file_created_during_snapshot(windows_vm_for_snapshot, windows_snapshot):
    file = f"{WINDOWS_DIRECTORY_PATH}\\file.txt"
    cmd = shlex.split(
        f'powershell -command "for($i=1; $i -le 100; $i++){{$i| Out-File -FilePath {file} -Append}}"',
    )
    run_ssh_commands(host=windows_vm_for_snapshot.ssh_exec, commands=cmd)
    windows_snapshot.wait_snapshot_done(timeout=TIMEOUT_10MIN)
    windows_vm_for_snapshot.stop(wait=True)
