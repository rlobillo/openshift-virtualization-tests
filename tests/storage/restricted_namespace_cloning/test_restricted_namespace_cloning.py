"""
Restricted namespace cloning
"""

import logging

import pytest
from kubernetes.client.rest import ApiException

from tests.storage import utils
from tests.storage.constants import DV_PARAMS, NAMESPACE_PARAMS
from tests.storage.restricted_namespace_cloning.constants import (
    ALL,
    CREATE,
    CREATE_DELETE,
    CREATE_DELETE_LIST_GET,
    DATAVOLUMES,
    DATAVOLUMES_AND_DVS_SRC,
    DATAVOLUMES_SRC,
    PERMISSIONS_DST,
    PERMISSIONS_SRC,
    PVC,
    TARGET_DV,
    VERBS_DST,
    VERBS_SRC,
)
from tests.storage.utils import verify_snapshot_used_namespace_transfer
from utilities.storage import ErrorMsg, create_dv


LOGGER = logging.getLogger(__name__)

pytestmark = pytest.mark.usefixtures("skip_when_no_unprivileged_client_available")


def create_dv_negative(
    namespace,
    storage_class_dict,
    size,
    source_pvc,
    source_namespace,
    unprivileged_client,
):
    with pytest.raises(
        ApiException,
        match=ErrorMsg.CANNOT_CREATE_RESOURCE,
    ):
        with create_dv(
            dv_name=TARGET_DV,
            namespace=namespace,
            source=PVC,
            size=size,
            source_pvc=source_pvc,
            source_namespace=source_namespace,
            client=unprivileged_client,
            storage_class=[*storage_class_dict][0],
        ):
            LOGGER.error("Target dv was created, but shouldn't have been")


@pytest.mark.sno
@pytest.mark.parametrize(
    "namespace, data_volume_multi_storage_scope_module",
    [
        pytest.param(
            NAMESPACE_PARAMS,
            DV_PARAMS,
            marks=pytest.mark.polarion("CNV-2688"),
        ),
    ],
    indirect=True,
)
def test_unprivileged_user_clone_same_namespace_negative(
    storage_class_matrix__module__,
    namespace,
    data_volume_multi_storage_scope_module,
    unprivileged_client,
):
    create_dv_negative(
        namespace=namespace.name,
        storage_class_dict=storage_class_matrix__module__,
        size=data_volume_multi_storage_scope_module.size,
        source_pvc=data_volume_multi_storage_scope_module.pvc.name,
        source_namespace=namespace.name,
        unprivileged_client=unprivileged_client,
    )


@pytest.mark.sno
@pytest.mark.parametrize(
    "namespace, data_volume_multi_storage_scope_module, permissions_src",
    [
        pytest.param(
            NAMESPACE_PARAMS,
            DV_PARAMS,
            {PERMISSIONS_SRC: DATAVOLUMES_AND_DVS_SRC, VERBS_SRC: ALL},
            marks=pytest.mark.polarion("CNV-8905"),
        ),
    ],
    indirect=True,
)
def test_unprivileged_user_clone_same_namespace_positive(
    storage_class_matrix__module__,
    namespace,
    data_volume_multi_storage_scope_module,
    unprivileged_client,
    permissions_src,
):
    with create_dv(
        dv_name=TARGET_DV,
        namespace=namespace.name,
        source=PVC,
        size=data_volume_multi_storage_scope_module.size,
        source_pvc=data_volume_multi_storage_scope_module.pvc.name,
        source_namespace=namespace.name,
        client=unprivileged_client,
        storage_class=[*storage_class_matrix__module__][0],
    ) as cdv:
        cdv.wait_for_dv_success()
        with utils.create_vm_from_dv(dv=cdv):
            return


@pytest.mark.sno
@pytest.mark.parametrize(
    "namespace, data_volume_multi_storage_scope_module",
    [
        pytest.param(
            NAMESPACE_PARAMS,
            DV_PARAMS,
            marks=pytest.mark.polarion("CNV-8906"),
        ),
    ],
    indirect=True,
)
def test_unprivileged_user_clone_different_namespaces_negative(
    storage_class_matrix__module__,
    namespace,
    data_volume_multi_storage_scope_module,
    unprivileged_client,
    dst_ns,
):
    create_dv_negative(
        namespace=dst_ns.name,
        storage_class_dict=storage_class_matrix__module__,
        size=data_volume_multi_storage_scope_module.size,
        source_pvc=data_volume_multi_storage_scope_module.pvc.name,
        source_namespace=namespace.name,
        unprivileged_client=unprivileged_client,
    )


@pytest.mark.sno
@pytest.mark.parametrize(
    "namespace, data_volume_multi_storage_scope_module, permissions_src, permissions_dst",
    [
        pytest.param(
            NAMESPACE_PARAMS,
            DV_PARAMS,
            {PERMISSIONS_SRC: DATAVOLUMES_AND_DVS_SRC, VERBS_SRC: CREATE_DELETE},
            {
                PERMISSIONS_DST: DATAVOLUMES_AND_DVS_SRC,
                VERBS_DST: CREATE_DELETE_LIST_GET,
            },
            marks=pytest.mark.polarion("CNV-2689"),
            id="src_ns: dv and dv/src, verbs: create, delete. dst: dv and dv/src, verbs: create, delete, list, get.",
        ),
        pytest.param(
            NAMESPACE_PARAMS,
            DV_PARAMS,
            {PERMISSIONS_SRC: DATAVOLUMES_AND_DVS_SRC, VERBS_SRC: ALL},
            {PERMISSIONS_DST: DATAVOLUMES_AND_DVS_SRC, VERBS_DST: ALL},
            marks=pytest.mark.polarion("CNV-2692"),
            id="src_ns: dv and dv/src, verbs: *. dst: dv and dv/src, verbs: *.",
        ),
        pytest.param(
            NAMESPACE_PARAMS,
            DV_PARAMS,
            {PERMISSIONS_SRC: DATAVOLUMES_AND_DVS_SRC, VERBS_SRC: ALL},
            {PERMISSIONS_DST: DATAVOLUMES, VERBS_DST: ALL},
            marks=pytest.mark.polarion("CNV-2805"),
            id="src_ns: dv and dv/src, verbs: *. dst: dv, verbs: *.",
        ),
        pytest.param(
            NAMESPACE_PARAMS,
            DV_PARAMS,
            {PERMISSIONS_SRC: DATAVOLUMES_AND_DVS_SRC, VERBS_SRC: CREATE_DELETE},
            {PERMISSIONS_DST: DATAVOLUMES, VERBS_DST: CREATE_DELETE_LIST_GET},
            marks=pytest.mark.polarion("CNV-2808"),
            id="src_ns: dv and dv/src, verbs: create, delete. dst: dv, verbs: create, delete, list, get.",
        ),
        pytest.param(
            NAMESPACE_PARAMS,
            DV_PARAMS,
            {PERMISSIONS_SRC: DATAVOLUMES_SRC, VERBS_SRC: CREATE},
            {PERMISSIONS_DST: DATAVOLUMES, VERBS_DST: CREATE_DELETE_LIST_GET},
            marks=pytest.mark.polarion("CNV-2971"),
            id="src_ns: dv/src, verbs: create. dst: dv, verbs: create, delete, list, get.",
        ),
    ],
    indirect=True,
)
def test_user_permissions_positive(
    storage_class_matrix__module__,
    namespace,
    data_volume_multi_storage_scope_module,
    dst_ns,
    unprivileged_client,
    permissions_src,
    permissions_dst,
):
    with create_dv(
        dv_name=TARGET_DV,
        namespace=dst_ns.name,
        source=PVC,
        size=data_volume_multi_storage_scope_module.size,
        source_pvc=data_volume_multi_storage_scope_module.pvc.name,
        source_namespace=namespace.name,
        client=unprivileged_client,
        storage_class=[*storage_class_matrix__module__][0],
    ) as cdv:
        cdv.wait_for_dv_success()
        verify_snapshot_used_namespace_transfer(
            cdv=cdv, unprivileged_client=unprivileged_client
        )
        with utils.create_vm_from_dv(dv=cdv):
            return


@pytest.mark.sno
@pytest.mark.parametrize(
    "namespace, data_volume_multi_storage_scope_module, permissions_src, permissions_dst",
    [
        pytest.param(
            NAMESPACE_PARAMS,
            DV_PARAMS,
            {PERMISSIONS_SRC: DATAVOLUMES, VERBS_SRC: CREATE_DELETE},
            {PERMISSIONS_DST: DATAVOLUMES, VERBS_DST: CREATE_DELETE},
            marks=pytest.mark.polarion("CNV-2793"),
            id="src_ns: dv, verbs: create, delete. dst: dv, verbs: create, delete.",
        ),
        pytest.param(
            NAMESPACE_PARAMS,
            DV_PARAMS,
            {PERMISSIONS_SRC: DATAVOLUMES, VERBS_SRC: ["list", "get"]},
            {PERMISSIONS_DST: DATAVOLUMES_AND_DVS_SRC, VERBS_DST: ALL},
            marks=pytest.mark.polarion("CNV-2691"),
            id="src_ns: dv, verbs: list, get. dst: dv and dv/src, verbs: *.",
        ),
        pytest.param(
            NAMESPACE_PARAMS,
            DV_PARAMS,
            {PERMISSIONS_SRC: DATAVOLUMES, VERBS_SRC: ALL},
            {PERMISSIONS_DST: DATAVOLUMES, VERBS_DST: ALL},
            marks=pytest.mark.polarion("CNV-2804"),
            id="src_ns: dv, verbs: *. dst: dv, verbs: *.",
        ),
    ],
    indirect=True,
)
def test_user_permissions_negative(
    storage_class_matrix__module__,
    namespace,
    data_volume_multi_storage_scope_module,
    dst_ns,
    unprivileged_client,
    permissions_src,
    permissions_dst,
):
    create_dv_negative(
        namespace=dst_ns.name,
        storage_class_dict=storage_class_matrix__module__,
        size=data_volume_multi_storage_scope_module.size,
        source_pvc=data_volume_multi_storage_scope_module.pvc.name,
        source_namespace=namespace.name,
        unprivileged_client=unprivileged_client,
    )


@pytest.mark.sno
@pytest.mark.parametrize(
    "namespace, data_volume_multi_storage_scope_module, permissions_dst",
    [
        pytest.param(
            NAMESPACE_PARAMS,
            DV_PARAMS,
            {PERMISSIONS_DST: DATAVOLUMES_AND_DVS_SRC, VERBS_DST: ALL},
            marks=pytest.mark.polarion("CNV-8907"),
        ),
    ],
    indirect=True,
)
def test_user_permissions_only_for_dst_ns_negative(
    storage_class_matrix__module__,
    namespace,
    data_volume_multi_storage_scope_module,
    dst_ns,
    unprivileged_client,
    permissions_dst,
):
    create_dv_negative(
        namespace=dst_ns.name,
        storage_class_dict=storage_class_matrix__module__,
        size=data_volume_multi_storage_scope_module.size,
        source_pvc=data_volume_multi_storage_scope_module.pvc.name,
        source_namespace=namespace.name,
        unprivileged_client=unprivileged_client,
    )
