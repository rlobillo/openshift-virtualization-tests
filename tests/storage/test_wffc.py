# -*- coding: utf-8 -*-

"""
HonorWaitForFirstConsumer test suite
"""

import logging

import pytest
from ocp_resources.cdi import CDI
from ocp_resources.datavolume import DataVolume
from ocp_resources.persistent_volume_claim import PersistentVolumeClaim
from ocp_resources.virtual_machine_instance import VirtualMachineInstance

import tests.storage.utils as storage_utils
from utilities.constants import (
    OS_FLAVOR_CIRROS,
    TIMEOUT_2MIN,
    TIMEOUT_10MIN,
    TIMEOUT_10SEC,
    Images,
)
from utilities.hco import (
    ResourceEditorValidateHCOReconcile,
    hco_cr_jsonpatch_annotations_dict,
)
from utilities.infra import cluster_resource
from utilities.storage import (
    cdi_feature_gate_list_with_added_feature,
    check_cdi_feature_gate_enabled,
    check_upload_virtctl_result,
    create_dv,
    downloaded_image,
    get_images_server_url,
    virtctl_upload_dv,
)
from utilities.virt import VirtualMachineForTests, running_vm, wait_for_ssh_connectivity


pytestmark = [
    pytest.mark.usefixtures("skip_test_if_no_hpp_sc"),
    pytest.mark.post_upgrade,
]

LOGGER = logging.getLogger(__name__)


WFFC_DV_NAME = "wffc-dv-name"
REMOTE_PATH = f"{Images.Cirros.DIR}/{Images.Cirros.QCOW2_IMG}"
DV_PARAMS = {
    "dv_name": "dv-wffc-tests",
    "image": REMOTE_PATH,
    "dv_size": Images.Cirros.DEFAULT_DV_SIZE,
}


@pytest.fixture(scope="module")
def enable_wffc_feature_gate(hyperconverged_resource_scope_module, cdi_config):
    honor_wffc = "HonorWaitForFirstConsumer"
    if check_cdi_feature_gate_enabled(feature=honor_wffc):
        yield
    else:
        # Feature gate wasn't enabled
        with ResourceEditorValidateHCOReconcile(
            patches={
                hyperconverged_resource_scope_module: hco_cr_jsonpatch_annotations_dict(
                    component="cdi",
                    path="featureGates",
                    value=cdi_feature_gate_list_with_added_feature(feature=honor_wffc),
                    op="replace",
                )
            },
            list_resource_reconcile=[CDI],
        ):
            yield


def get_dv_template_dict(dv_name, storage_class):
    return {
        "metadata": {
            "name": f"{dv_name}",
        },
        "spec": {
            "pvc": {
                "volumeMode": DataVolume.VolumeMode.FILE,
                "accessModes": [DataVolume.AccessMode.RWO],
                "resources": {"requests": {"storage": Images.Cirros.DEFAULT_DV_SIZE}},
                "storageClassName": storage_class,
            },
            "source": {
                "http": {"url": f"{get_images_server_url(schema='http')}{REMOTE_PATH}"}
            },
        },
    }


def _valid_vm_and_disk_count(vm):
    running_vm(vm=vm, wait_for_interfaces=False)
    storage_utils.check_disk_count_in_vm(vm=vm)


@pytest.fixture(scope="class")
def downloaded_image_full_path(tmpdir_factory):
    return tmpdir_factory.mktemp("wffc_upload").join(Images.Cirros.QCOW2_IMG)


@pytest.fixture(scope="class")
def uploaded_wffc_dv(namespace):
    return cluster_resource(DataVolume)(namespace=namespace.name, name=WFFC_DV_NAME)


@pytest.fixture(scope="class")
def downloaded_image_scope_class(downloaded_image_full_path):
    downloaded_image(
        remote_name=REMOTE_PATH,
        local_name=downloaded_image_full_path,
    )


@pytest.fixture(scope="class")
def uploaded_dv_via_virtctl_wffc(
    namespace,
    downloaded_image_full_path,
    downloaded_image_scope_class,
    storage_class_matrix_hpp_matrix__module__,
):
    with virtctl_upload_dv(
        namespace=namespace.name,
        name=WFFC_DV_NAME,
        size=Images.Cirros.DEFAULT_DV_SIZE,
        image_path=downloaded_image_full_path,
        storage_class=[*storage_class_matrix_hpp_matrix__module__][0],
        insecure=True,
        consume_wffc=False,
    ) as res:
        yield res


@pytest.fixture()
def vm_from_uploaded_dv(namespace, uploaded_dv_via_virtctl_wffc, uploaded_wffc_dv):
    with storage_utils.create_vm_from_dv(
        dv=uploaded_wffc_dv,
        vm_name=WFFC_DV_NAME,
        start=False,
    ) as vm_dv:
        vm_dv.start(wait=False)
        vm_dv.vmi.wait_for_status(status=VirtualMachineInstance.Status.PENDING)
        uploaded_wffc_dv.pvc.wait_for_status(
            status=PersistentVolumeClaim.Status.BOUND, timeout=TIMEOUT_10SEC
        )
        yield vm_dv


class TestWFFCUploadVirtctl:
    @pytest.mark.sno
    @pytest.mark.polarion("CNV-4711")
    def test_wffc_fail_to_upload_dv_via_virtctl(
        self,
        skip_when_hpp_no_waitforfirstconsumer,
        namespace,
        enable_wffc_feature_gate,
        uploaded_dv_via_virtctl_wffc,
        uploaded_wffc_dv,
    ):
        check_upload_virtctl_result(
            result=uploaded_dv_via_virtctl_wffc,
            expected_success=False,
            expected_output="cannot upload to DataVolume in WaitForFirstConsumer state, make sure the PVC is Bound",
            assert_message="Upload DV via virtctl, with wffc SC binding mode ended up with success instead of failure",
        )
        pending_status = uploaded_wffc_dv.pvc.Status.PENDING
        wffc_status = uploaded_wffc_dv.Status.WAIT_FOR_FIRST_CONSUMER
        assert (
            uploaded_wffc_dv.pvc.status == pending_status
        ), f"The status of PVC {uploaded_wffc_dv.pvc.name}:{uploaded_wffc_dv.pvc.status} and not {pending_status}"
        assert (
            uploaded_wffc_dv.status == wffc_status
        ), f"The status of DV {uploaded_wffc_dv.name}:{uploaded_wffc_dv.status} and not {wffc_status}"

    @pytest.mark.sno
    @pytest.mark.polarion("CNV-7413")
    def test_wffc_create_vm_from_uploaded_dv_via_virtctl(
        self,
        skip_when_hpp_no_waitforfirstconsumer,
        enable_wffc_feature_gate,
        downloaded_image_full_path,
        vm_from_uploaded_dv,
        storage_class_matrix_hpp_matrix__module__,
    ):
        with virtctl_upload_dv(
            namespace=vm_from_uploaded_dv.namespace,
            name=WFFC_DV_NAME,
            size=Images.Cirros.DEFAULT_DV_SIZE,
            image_path=downloaded_image_full_path,
            storage_class=[*storage_class_matrix_hpp_matrix__module__][0],
            insecure=True,
            consume_wffc=False,
            cleanup=False,
        ) as res:
            check_upload_virtctl_result(result=res)
            vm_from_uploaded_dv.vmi.wait_until_running()
            wait_for_ssh_connectivity(vm=vm_from_uploaded_dv, timeout=TIMEOUT_2MIN)
            storage_utils.check_disk_count_in_vm(vm=vm_from_uploaded_dv)


@pytest.mark.sno
@pytest.mark.parametrize(
    "data_volume_multi_hpp_storage",
    [
        pytest.param(
            {**DV_PARAMS, **{"consume_wffc": True}},
            marks=pytest.mark.polarion("CNV-4371"),
        ),
    ],
    indirect=True,
)
def test_wffc_import_http_dv(
    skip_when_hpp_no_waitforfirstconsumer,
    enable_wffc_feature_gate,
    data_volume_multi_hpp_storage,
):
    with storage_utils.create_vm_from_dv(
        dv=data_volume_multi_hpp_storage, vm_name=data_volume_multi_hpp_storage.name
    ) as vm_dv:
        storage_utils.check_disk_count_in_vm(vm=vm_dv)


@pytest.mark.sno
@pytest.mark.polarion("CNV-4739")
def test_wffc_import_registry_dv(
    skip_when_hpp_no_waitforfirstconsumer,
    enable_wffc_feature_gate,
    namespace,
    storage_class_matrix_hpp_matrix__module__,
):
    dv_name = "cnv-4739"
    with create_dv(
        source="registry",
        dv_name=dv_name,
        namespace=namespace.name,
        url=f"docker://quay.io/kubevirt/{Images.Cirros.DISK_DEMO}",
        storage_class=[*storage_class_matrix_hpp_matrix__module__][0],
        consume_wffc=True,
    ) as dv:
        dv.wait_for_dv_success()
        with storage_utils.create_vm_from_dv(dv=dv, vm_name=dv_name) as vm_dv:
            storage_utils.check_disk_count_in_vm(vm=vm_dv)


@pytest.mark.sno
@pytest.mark.polarion("CNV-4741")
def test_wffc_upload_dv_via_token(
    skip_when_hpp_no_waitforfirstconsumer,
    enable_wffc_feature_gate,
    namespace,
    unprivileged_client,
    tmpdir,
    storage_class_matrix_hpp_matrix__module__,
):
    dv_name = "cnv-4741"
    local_name = f"{tmpdir}/{Images.Cirros.QCOW2_IMG}"
    downloaded_image(
        remote_name=REMOTE_PATH,
        local_name=local_name,
    )
    with storage_utils.upload_image_to_dv(
        dv_name=dv_name,
        storage_class=[*storage_class_matrix_hpp_matrix__module__][0],
        storage_ns_name=namespace.name,
        client=unprivileged_client,
        consume_wffc=True,
    ) as dv:
        storage_utils.upload_token_request(
            storage_ns_name=namespace.name, pvc_name=dv.pvc.name, data=local_name
        )
        dv.wait_for_dv_success()
        with storage_utils.create_vm_from_dv(dv=dv, vm_name=dv_name) as vm_dv:
            storage_utils.check_disk_count_in_vm(vm=vm_dv)


@pytest.mark.sno
@pytest.mark.parametrize(
    "data_volume_multi_hpp_storage",
    [
        pytest.param(
            {**DV_PARAMS, **{"consume_wffc": True}},
            marks=pytest.mark.polarion("CNV-4379"),
        ),
    ],
    indirect=True,
)
def test_wffc_clone_dv(
    skip_when_hpp_no_waitforfirstconsumer,
    enable_wffc_feature_gate,
    data_volume_multi_hpp_storage,
):
    with create_dv(
        source="pvc",
        dv_name="dv-target",
        namespace=data_volume_multi_hpp_storage.namespace,
        size=data_volume_multi_hpp_storage.size,
        source_pvc=data_volume_multi_hpp_storage.name,
        storage_class=data_volume_multi_hpp_storage.storage_class,
        consume_wffc=True,
    ) as cdv:
        cdv.wait_for_dv_success(timeout=TIMEOUT_10MIN)
        with storage_utils.create_vm_from_dv(dv=cdv, vm_name=cdv.name) as vm_dv:
            storage_utils.check_disk_count_in_vm(vm=vm_dv)


@pytest.mark.sno
@pytest.mark.parametrize(
    "data_volume_multi_hpp_storage",
    [
        pytest.param(
            {**DV_PARAMS, **{"consume_wffc": False}},
            marks=pytest.mark.polarion("CNV-4742"),
        ),
    ],
    indirect=True,
)
def test_wffc_add_dv_to_vm_with_data_volume_template(
    skip_when_hpp_no_waitforfirstconsumer,
    enable_wffc_feature_gate,
    namespace,
    data_volume_multi_hpp_storage,
):
    with cluster_resource(VirtualMachineForTests)(
        name="cnv-4742-vm",
        namespace=namespace.name,
        os_flavor=OS_FLAVOR_CIRROS,
        data_volume_template=get_dv_template_dict(
            dv_name="template-dv",
            storage_class=data_volume_multi_hpp_storage.storage_class,
        ),
        memory_requests=Images.Cirros.DEFAULT_MEMORY_SIZE,
    ) as vm:
        _valid_vm_and_disk_count(vm=vm)
        # Add DV
        vm.stop(wait=True)
        storage_utils.add_dv_to_vm(vm=vm, dv_name=data_volume_multi_hpp_storage.name)
        # Check DV was added
        _valid_vm_and_disk_count(vm=vm)


@pytest.mark.sno
@pytest.mark.polarion("CNV-4743")
def test_wffc_vm_with_two_data_volume_templates(
    skip_when_hpp_no_waitforfirstconsumer,
    enable_wffc_feature_gate,
    namespace,
    storage_class_matrix_hpp_matrix__module__,
):
    storage_class = [*storage_class_matrix_hpp_matrix__module__][0]
    with cluster_resource(VirtualMachineForTests)(
        name="cnv-4743-vm",
        namespace=namespace.name,
        os_flavor=OS_FLAVOR_CIRROS,
        data_volume_template=get_dv_template_dict(
            dv_name="template-dv-1",
            storage_class=storage_class,
        ),
        memory_requests=Images.Cirros.DEFAULT_MEMORY_SIZE,
    ) as vm:
        storage_utils.add_dv_to_vm(
            vm=vm,
            template_dv=get_dv_template_dict(
                dv_name="template-dv-2",
                storage_class=storage_class,
            ),
        )
        _valid_vm_and_disk_count(vm=vm)
