import pytest
from ocp_resources.persistent_volume_claim import PersistentVolumeClaim

from utilities.constants import TIMEOUT_2MIN, TIMEOUT_8MIN
from utilities.virt import running_vm


pytestmark = pytest.mark.usefixtures("skip_if_no_storage_class_for_snapshot")


@pytest.mark.polarion("CNV-8580")
def test_backup_while_dv_create(
    imported_dv_in_progress,
    restore_single_ns,
    storage_class_matrix_snapshot_matrix__function__,
):
    imported_dv_in_progress.wait_for_dv_success(timeout=TIMEOUT_8MIN)


@pytest.mark.polarion("CNV-8695")
def test_restore_multiple_ns(
    restore_multiple_ns, imported_dv_in_progress, rhel_vm_for_backup
):
    assert (
        imported_dv_in_progress.instance.status.phase
        == imported_dv_in_progress.Status.SUCCEEDED
    )
    running_vm(vm=rhel_vm_for_backup)


@pytest.mark.polarion("CNV-9078")
def test_backup_exclude_pvc(restore_exclude_pvc, imported_dv_in_progress):
    imported_dv_in_progress.wait_for_status(
        status=imported_dv_in_progress.Status.PENDING,
        timeout=TIMEOUT_2MIN,
        stop_status=imported_dv_in_progress.Status.SUCCEEDED,
    )
    assert not PersistentVolumeClaim(
        namespace=imported_dv_in_progress.namespace, name=imported_dv_in_progress.name
    ).exists
