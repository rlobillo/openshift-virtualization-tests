import pytest
from ocp_resources.datavolume import DataVolume
from ocp_resources.namespace import Namespace
from ocp_resources.persistent_volume_claim import PersistentVolumeClaim
from ocp_resources.template import Template
from pytest_testconfig import config as py_config

from tests.storage.oadp.utils import VeleroBackup, VeleroRestore
from utilities.constants import TIMEOUT_10MIN, Images
from utilities.infra import cluster_resource
from utilities.storage import create_dv
from utilities.virt import VirtualMachineForTestsFromTemplate, running_vm


@pytest.fixture()
def imported_dv_in_progress(
    rhel9_http_image_url,
    namespace_for_backup,
    storage_class_matrix_snapshot_matrix__function__,
):
    with create_dv(
        source="http",
        dv_name="imported-dv",
        namespace=namespace_for_backup.name,
        url=rhel9_http_image_url,
        size=Images.Rhel.DEFAULT_DV_SIZE,
        storage_class=[*storage_class_matrix_snapshot_matrix__function__][0],
    ) as dv:
        yield dv


@pytest.fixture()
def namespace_for_backup(admin_client):
    with cluster_resource(Namespace)(client=admin_client, name="velero-test-ns") as ns:
        yield ns


@pytest.fixture()
def backup_single_ns(admin_client, namespace_for_backup):
    with cluster_resource(VeleroBackup)(
        included_namespaces=[
            namespace_for_backup.name,
        ],
        name="backup-ns",
        client=admin_client,
    ) as backup:
        yield backup


@pytest.fixture()
def namespace_for_backup2(admin_client):
    with cluster_resource(Namespace)(client=admin_client, name="velero-test-ns2") as ns:
        yield ns


@pytest.fixture()
def restore_single_ns(admin_client, backup_single_ns):
    # Delete NS in order to restore it
    cluster_resource(Namespace)(
        client=admin_client, name=backup_single_ns.included_namespaces[0]
    ).delete(wait=True)
    with cluster_resource(VeleroRestore)(
        included_namespaces=backup_single_ns.included_namespaces,
        name="restore-ns",
        client=admin_client,
        backup_name=backup_single_ns.name,
    ) as restore:
        yield restore


@pytest.fixture()
def rhel_dv_dict(
    storage_class_matrix_snapshot_matrix__function__,
    admin_client,
    namespace_for_backup2,
    rhel9_http_image_url,
):
    dv = cluster_resource(DataVolume)(
        name="dv-from-template",
        namespace=namespace_for_backup2.name,
        storage_class=[*storage_class_matrix_snapshot_matrix__function__][0],
        source="http",
        url=rhel9_http_image_url,
        size=Images.Rhel.DEFAULT_DV_SIZE,
        client=admin_client,
        api_name="storage",
    )
    dv.to_dict()
    return dv.res


@pytest.fixture()
def rhel_vm_for_backup(admin_client, rhel_dv_dict):
    dv_metadata = rhel_dv_dict["metadata"]
    with cluster_resource(VirtualMachineForTestsFromTemplate)(
        name="rhel-vm",
        namespace=dv_metadata["namespace"],
        client=admin_client,
        labels=Template.generate_template_labels(
            **py_config["latest_rhel_os_dict"]["template_labels"]
        ),
        data_volume_template={"metadata": dv_metadata, "spec": rhel_dv_dict["spec"]},
    ) as vm:
        running_vm(vm=vm)
        yield vm


@pytest.fixture()
def backup_multiple_ns(admin_client, imported_dv, rhel_vm_for_backup):
    with cluster_resource(VeleroBackup)(
        included_namespaces=[
            imported_dv.namespace,
            rhel_vm_for_backup.namespace,
        ],
        name="backup-multiple-ns",
        client=admin_client,
    ) as backup:
        yield backup


@pytest.fixture()
def restore_multiple_ns(admin_client, backup_multiple_ns):
    # Delete NS in order to restore it
    for ns in backup_multiple_ns.included_namespaces:
        cluster_resource(Namespace)(client=admin_client, name=ns).delete(wait=True)
    with cluster_resource(VeleroRestore)(
        included_namespaces=backup_multiple_ns.included_namespaces,
        name="restore-multiple-ns",
        client=admin_client,
        backup_name=backup_multiple_ns.name,
    ) as restore:
        yield restore


@pytest.fixture()
def imported_dv(imported_dv_in_progress):
    imported_dv_in_progress.wait_for_dv_success(timeout=TIMEOUT_10MIN)
    yield imported_dv_in_progress


@pytest.fixture()
def backup_exclude_pvc(imported_dv, admin_client, namespace_for_backup):
    with cluster_resource(VeleroBackup)(
        included_namespaces=[
            namespace_for_backup.name,
        ],
        name="backup-exclude-pvc",
        client=admin_client,
        excluded_resources=[
            PersistentVolumeClaim.kind,
        ],
    ) as backup:
        yield backup


@pytest.fixture()
def restore_exclude_pvc(admin_client, backup_exclude_pvc):
    cluster_resource(Namespace)(
        client=admin_client, name=backup_exclude_pvc.included_namespaces[0]
    ).delete(wait=True)
    with cluster_resource(VeleroRestore)(
        included_namespaces=backup_exclude_pvc.included_namespaces,
        name="restore-exclude-pvc",
        client=admin_client,
        backup_name=backup_exclude_pvc.name,
    ) as restore:
        yield restore
