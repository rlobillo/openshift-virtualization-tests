import logging

import pytest
from kubernetes.client.rest import ApiException
from ocp_resources.datavolume import DataVolume
from ocp_resources.persistent_volume_claim import PersistentVolumeClaim
from pytest_testconfig import config as py_config

from tests.os_params import RHEL_LATEST, RHEL_LATEST_LABELS
from utilities.constants import TIMEOUT_20MIN
from utilities.infra import cluster_resource
from utilities.storage import ErrorMsg, create_dv, get_images_server_url
from utilities.virt import wait_for_ssh_connectivity


pytestmark = pytest.mark.post_upgrade


LOGGER = logging.getLogger(__name__)
LATEST_RHEL_IMAGE = RHEL_LATEST["image_path"]
RHEL_IMAGE_SIZE = RHEL_LATEST["dv_size"]
GOLDEN_IMAGES_NAMESPACE = py_config["golden_images_namespace"]


DV_PARAM = {
    "dv_name": "golden-image-dv",
    "image": LATEST_RHEL_IMAGE,
    "dv_size": RHEL_IMAGE_SIZE,
    "storage_class": py_config["default_storage_class"],
}


@pytest.mark.sno
@pytest.mark.polarion("CNV-4755")
def test_regular_user_cant_create_dv_in_ns(
    golden_images_namespace,
    unprivileged_client,
):
    LOGGER.info(
        "Try as a regular user, to create a DV in golden image NS and receive the proper error"
    )
    with pytest.raises(
        ApiException,
        match=ErrorMsg.CANNOT_CREATE_RESOURCE,
    ):
        with create_dv(
            client=unprivileged_client,
            dv_name="cnv-4755",
            namespace=golden_images_namespace.name,
            url=f"{get_images_server_url()}{LATEST_RHEL_IMAGE}",
            size=RHEL_IMAGE_SIZE,
            storage_class=py_config["default_storage_class"],
        ):
            return


@pytest.mark.sno
@pytest.mark.parametrize(
    "golden_image_data_volume_scope_module",
    [
        pytest.param(DV_PARAM, marks=pytest.mark.polarion("CNV-4756")),
    ],
    indirect=True,
)
def test_regular_user_cant_delete_dv_from_cloned_dv(
    golden_images_namespace,
    unprivileged_client,
    golden_image_data_volume_scope_module,
):
    LOGGER.info(
        "Try as a regular user, to delete a dv from golden image NS and receive the proper error"
    )
    with pytest.raises(
        ApiException,
        match=ErrorMsg.CANNOT_DELETE_RESOURCE,
    ):
        DataVolume(
            name=golden_image_data_volume_scope_module.name,
            namespace=golden_image_data_volume_scope_module.namespace,
            client=unprivileged_client,
        ).delete()


@pytest.mark.sno
@pytest.mark.parametrize(
    "golden_image_data_volume_multi_storage_scope_function,"
    "golden_image_vm_instance_from_template_multi_storage_scope_function",
    [
        pytest.param(
            {
                "dv_name": "cnv-4757",
                "image": LATEST_RHEL_IMAGE,
                "dv_size": RHEL_IMAGE_SIZE,
            },
            {
                "vm_name": "rhel-vm",
                "template_labels": RHEL_LATEST_LABELS,
            },
            marks=pytest.mark.polarion("CNV-4757"),
        ),
    ],
    indirect=True,
)
def test_regular_user_can_create_vm_from_cloned_dv(
    golden_image_data_volume_multi_storage_scope_function,
    golden_image_vm_instance_from_template_multi_storage_scope_function,
):
    wait_for_ssh_connectivity(
        vm=golden_image_vm_instance_from_template_multi_storage_scope_function
    )


@pytest.mark.sno
@pytest.mark.parametrize(
    "golden_image_data_volume_scope_module",
    [
        pytest.param(DV_PARAM, marks=pytest.mark.polarion("CNV-4758")),
    ],
    indirect=True,
)
def test_regular_user_can_list_all_pvc_in_ns(
    golden_images_namespace,
    unprivileged_client,
    golden_image_data_volume_scope_module,
):
    LOGGER.info(
        "Make sure regulr user have permissions to view PVC's in golden image NS"
    )
    assert list(
        cluster_resource(PersistentVolumeClaim).get(
            dyn_client=unprivileged_client,
            namespace=golden_images_namespace.name,
            field_selector=f"metadata.name=={golden_image_data_volume_scope_module.name}",
        )
    )


@pytest.mark.sno
@pytest.mark.parametrize(
    "golden_image_data_volume_scope_module",
    [
        pytest.param(DV_PARAM, marks=pytest.mark.polarion("CNV-4760")),
    ],
    indirect=True,
)
def test_regular_user_cant_clone_dv_in_ns(
    golden_images_namespace,
    unprivileged_client,
    golden_image_data_volume_scope_module,
):
    LOGGER.info(
        "Try to clone a DV in the golden image NS and fail with the proper message"
    )
    with pytest.raises(
        ApiException,
        match=ErrorMsg.CANNOT_CREATE_RESOURCE,
    ):
        with create_dv(
            dv_name="cloned-dv",
            namespace=golden_images_namespace.name,
            source="pvc",
            size=golden_image_data_volume_scope_module.size,
            source_pvc=golden_image_data_volume_scope_module.pvc.name,
            source_namespace=golden_image_data_volume_scope_module.namespace,
            client=unprivileged_client,
            storage_class=golden_image_data_volume_scope_module.storage_class,
        ):
            return


@pytest.mark.sno
@pytest.mark.polarion("CNV-5275")
def test_regular_user_can_create_dv_in_ns_given_proper_rolebinding(
    golden_images_namespace,
    golden_images_edit_rolebinding,
    unprivileged_client,
    storage_class_matrix__function__,
):
    LOGGER.info(
        "Once a proper RoleBinding created, that use the os-images.kubevirt.io:edit\
        ClusterRole, a regular user can create a DV in the golden image NS.",
    )
    with create_dv(
        client=unprivileged_client,
        dv_name="cnv-5275",
        namespace=golden_images_namespace.name,
        url=f"{get_images_server_url()}{LATEST_RHEL_IMAGE}",
        size=RHEL_IMAGE_SIZE,
        storage_class=[*storage_class_matrix__function__][0],
    ) as dv:
        dv.wait_for_dv_success(timeout=TIMEOUT_20MIN)
