"""
Restricted namespace cloning
"""

import logging

import pytest
from kubernetes.client.rest import ApiException
from ocp_resources.datavolume import DataVolume
from ocp_resources.service_account import ServiceAccount

from tests.storage.constants import DV_PARAMS, NAMESPACE_PARAMS
from tests.storage.restricted_namespace_cloning.constants import (
    ALL,
    CREATE,
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
from tests.storage.utils import (
    create_cluster_role,
    create_dv,
    create_role_binding,
    create_vm_and_verify_image_permission,
    set_permissions,
    verify_snapshot_used_namespace_transfer,
)
from utilities.constants import OS_FLAVOR_CIRROS, Images
from utilities.infra import cluster_resource
from utilities.storage import ErrorMsg, sc_is_hpp_with_immediate_volume_binding
from utilities.virt import VirtualMachineForTests


PERMISSIONS_SRC_SA = "permissions_src_sa"
PERMISSIONS_DST_SA = "permissions_dst_sa"
VERBS_SRC_SA = "verbs_src_sa"
VERBS_DST_SA = "verbs_dst_sa"
VM_FOR_TEST = "vm-for-test"
METADATA = "metadata"
SPEC = "spec"

pytestmark = [
    pytest.mark.usefixtures("skip_when_no_unprivileged_client_available"),
    pytest.mark.post_upgrade,
]


LOGGER = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def restricted_ns_service_account(dst_ns):
    with cluster_resource(ServiceAccount)(
        name="vm-service-account", namespace=dst_ns.name
    ) as sa:
        yield sa


@pytest.fixture(scope="module")
def cluster_role_for_creating_pods():
    with create_cluster_role(
        name="pod-creator",
        api_groups=[""],
        verbs=CREATE,
        permissions_to_resources=["pods"],
    ) as cluster_role_pod_creator:
        yield cluster_role_pod_creator


@pytest.fixture()
def data_volume_clone_settings(
    namespace, dst_ns, data_volume_multi_storage_scope_module
):
    dv = DataVolume(
        name=TARGET_DV,
        namespace=dst_ns.name,
        source=PVC,
        source_pvc=data_volume_multi_storage_scope_module.name,
        source_namespace=namespace.name,
        volume_mode=data_volume_multi_storage_scope_module.volume_mode,
        access_modes=data_volume_multi_storage_scope_module.access_modes,
        storage_class=data_volume_multi_storage_scope_module.storage_class,
        api_name="storage",
        size=data_volume_multi_storage_scope_module.size,
        hostpath_node=data_volume_multi_storage_scope_module.pvc.selected_node
        if sc_is_hpp_with_immediate_volume_binding(
            sc=data_volume_multi_storage_scope_module.storage_class
        )
        else None,
    )
    dv.to_dict()
    return dv


@pytest.fixture()
def allow_unprivileged_client_to_manage_vms_on_dst_ns(
    dst_ns, api_group, unprivileged_user_username
):
    with create_role_binding(
        name="allow_unprivileged_client_to_run_vms_on_dst_ns",
        namespace=dst_ns.name,
        subjects_kind="User",
        subjects_name=unprivileged_user_username,
        subjects_api_group=api_group,
        role_ref_kind="ClusterRole",
        role_ref_name="kubevirt.io:admin",
    ) as role_binding_vm_admin_unprivileged_client:
        yield role_binding_vm_admin_unprivileged_client


@pytest.fixture()
def permissions_src_sa(request, namespace, dst_ns, restricted_ns_service_account):
    with set_permissions(
        role_name="datavolume-cluster-role-src",
        verbs=request.param[VERBS_SRC_SA],
        permissions_to_resources=request.param[PERMISSIONS_SRC_SA],
        binding_name="role_bind_src",
        namespace=namespace.name,
        subjects_kind=restricted_ns_service_account.kind,
        subjects_name=restricted_ns_service_account.name,
        subjects_namespace=dst_ns.name,
    ):
        yield


@pytest.fixture()
def permissions_dst_sa(request, dst_ns, restricted_ns_service_account):
    with set_permissions(
        role_name="datavolume-cluster-role-dst",
        verbs=request.param[VERBS_DST_SA],
        permissions_to_resources=request.param[PERMISSIONS_DST_SA],
        binding_name="role_bind_dst",
        namespace=dst_ns.name,
        subjects_kind=restricted_ns_service_account.kind,
        subjects_name=restricted_ns_service_account.name,
        subjects_namespace=dst_ns.name,
    ):
        yield


@pytest.mark.sno
@pytest.mark.parametrize(
    "namespace, data_volume_multi_storage_scope_module, permissions_src_sa, permissions_dst_sa",
    [
        pytest.param(
            NAMESPACE_PARAMS,
            DV_PARAMS,
            {PERMISSIONS_SRC_SA: DATAVOLUMES_AND_DVS_SRC, VERBS_SRC_SA: ALL},
            {PERMISSIONS_DST_SA: DATAVOLUMES_AND_DVS_SRC, VERBS_DST_SA: ALL},
            marks=pytest.mark.polarion("CNV-2826"),
        )
    ],
    indirect=True,
)
def test_create_vm_with_cloned_data_volume_positive(
    namespace,
    dst_ns,
    restricted_ns_service_account,
    unprivileged_client,
    allow_unprivileged_client_to_manage_vms_on_dst_ns,
    data_volume_clone_settings,
    permissions_src_sa,
    permissions_dst_sa,
):
    with cluster_resource(VirtualMachineForTests)(
        name=VM_FOR_TEST,
        namespace=dst_ns.name,
        os_flavor=OS_FLAVOR_CIRROS,
        service_accounts=[restricted_ns_service_account.name],
        client=unprivileged_client,
        memory_requests=Images.Cirros.DEFAULT_MEMORY_SIZE,
        data_volume_template={
            METADATA: data_volume_clone_settings.res[METADATA],
            SPEC: data_volume_clone_settings.res[SPEC],
        },
    ) as vm:
        vm.start(wait=True)
        verify_snapshot_used_namespace_transfer(
            cdv=data_volume_clone_settings,
            unprivileged_client=unprivileged_client,
        )


@pytest.mark.parametrize(
    "namespace, data_volume_multi_storage_scope_module, permissions_src, permissions_dst",
    [
        pytest.param(
            NAMESPACE_PARAMS,
            DV_PARAMS,
            {PERMISSIONS_SRC: DATAVOLUMES_SRC, VERBS_SRC: ALL},
            {PERMISSIONS_DST: DATAVOLUMES, VERBS_DST: ALL},
            marks=pytest.mark.polarion("CNV-2828"),
        )
    ],
    indirect=True,
)
def test_create_vm_with_cloned_data_volume_grant_unprivileged_client_permissions_negative(
    namespace,
    dst_ns,
    restricted_ns_service_account,
    unprivileged_client,
    allow_unprivileged_client_to_manage_vms_on_dst_ns,
    data_volume_clone_settings,
    permissions_src,
    permissions_dst,
):
    with pytest.raises(
        ApiException,
        match=ErrorMsg.CANNOT_CREATE_RESOURCE,
    ):
        with cluster_resource(VirtualMachineForTests)(
            name=VM_FOR_TEST,
            namespace=dst_ns.name,
            os_flavor=OS_FLAVOR_CIRROS,
            service_accounts=[restricted_ns_service_account.name],
            client=unprivileged_client,
            memory_requests=Images.Cirros.DEFAULT_MEMORY_SIZE,
            data_volume_template={
                METADATA: data_volume_clone_settings.res[METADATA],
                SPEC: data_volume_clone_settings.res[SPEC],
            },
        ):
            return


@pytest.mark.parametrize(
    "namespace, data_volume_multi_storage_scope_module, permissions_src_sa, permissions_dst_sa",
    [
        pytest.param(
            NAMESPACE_PARAMS,
            DV_PARAMS,
            {PERMISSIONS_SRC_SA: DATAVOLUMES, VERBS_SRC_SA: ALL},
            {PERMISSIONS_DST_SA: DATAVOLUMES, VERBS_DST_SA: ALL},
            marks=pytest.mark.polarion("CNV-2827"),
        )
    ],
    indirect=True,
)
def test_create_vm_with_cloned_data_volume_restricted_ns_service_account_missing_cloning_permission_negative(
    namespace,
    dst_ns,
    restricted_ns_service_account,
    unprivileged_client,
    data_volume_clone_settings,
    permissions_src_sa,
    permissions_dst_sa,
):
    with pytest.raises(
        ApiException,
        match=ErrorMsg.CANNOT_CREATE_RESOURCE,
    ):
        with cluster_resource(VirtualMachineForTests)(
            name=VM_FOR_TEST,
            namespace=dst_ns.name,
            os_flavor=OS_FLAVOR_CIRROS,
            service_accounts=[restricted_ns_service_account.name],
            client=unprivileged_client,
            memory_requests=Images.Cirros.DEFAULT_MEMORY_SIZE,
            data_volume_template={
                METADATA: data_volume_clone_settings.res[METADATA],
                SPEC: data_volume_clone_settings.res[SPEC],
            },
        ):
            return


@pytest.mark.parametrize(
    "data_volume_multi_storage_scope_module, namespace",
    [
        pytest.param(
            DV_PARAMS, NAMESPACE_PARAMS, marks=pytest.mark.polarion("CNV-2829")
        ),
    ],
    indirect=True,
)
def test_create_vm_with_cloned_data_volume_permissions_for_pods_positive(
    namespace,
    dst_ns,
    restricted_ns_service_account,
    unprivileged_client,
    unprivileged_user_username,
    data_volume_clone_settings,
    cluster_role_for_creating_pods,
    allow_unprivileged_client_to_manage_vms_on_dst_ns,
):
    with create_role_binding(
        name="service-account-can-create-pods-on-src",
        namespace=namespace.name,
        subjects_kind=restricted_ns_service_account.kind,
        subjects_name=restricted_ns_service_account.name,
        role_ref_kind=cluster_role_for_creating_pods.kind,
        role_ref_name=cluster_role_for_creating_pods.name,
        subjects_namespace=dst_ns.name,
    ):
        with create_role_binding(
            name="service-account-can-create-pods-on-dst",
            namespace=dst_ns.name,
            subjects_kind=restricted_ns_service_account.kind,
            subjects_name=restricted_ns_service_account.name,
            role_ref_kind=cluster_role_for_creating_pods.kind,
            role_ref_name=cluster_role_for_creating_pods.name,
            subjects_namespace=dst_ns.name,
        ):
            with cluster_resource(VirtualMachineForTests)(
                name=VM_FOR_TEST,
                namespace=dst_ns.name,
                os_flavor=OS_FLAVOR_CIRROS,
                service_accounts=[restricted_ns_service_account.name],
                client=unprivileged_client,
                memory_requests=Images.Cirros.DEFAULT_MEMORY_SIZE,
                data_volume_template={
                    METADATA: data_volume_clone_settings.res[METADATA],
                    SPEC: data_volume_clone_settings.res[SPEC],
                },
            ) as vm:
                vm.start(wait=True)
                verify_snapshot_used_namespace_transfer(
                    cdv=data_volume_clone_settings,
                    unprivileged_client=unprivileged_client,
                )


@pytest.mark.parametrize(
    "namespace, data_volume_multi_storage_scope_module, permissions_src, permissions_dst",
    [
        pytest.param(
            NAMESPACE_PARAMS,
            DV_PARAMS,
            {PERMISSIONS_SRC: DATAVOLUMES_AND_DVS_SRC, VERBS_SRC: ALL},
            {PERMISSIONS_DST: DATAVOLUMES_AND_DVS_SRC, VERBS_DST: ALL},
            marks=pytest.mark.polarion("CNV-4034"),
        )
    ],
    indirect=True,
)
def test_disk_image_after_create_vm_with_restricted_clone(
    skip_block_volumemode_scope_module,
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
        cdv.wait()
        create_vm_and_verify_image_permission(dv=cdv)
