# -*- coding: utf-8 -*-

"""
Clone tests
"""

import pytest
from ocp_resources.datavolume import DataVolume
from ocp_resources.utils import TimeoutSampler
from ocp_resources.volume_snapshot import VolumeSnapshot
from pytest_testconfig import config as py_config

from tests.storage import utils
from tests.storage.utils import (
    create_cirros_dv,
    get_storage_class_with_specified_volume_mode,
)
from utilities.constants import (
    OS_FLAVOR_CIRROS,
    OS_FLAVOR_WINDOWS,
    TIMEOUT_5MIN,
    TIMEOUT_10MIN,
    TIMEOUT_40MIN,
    Images,
)
from utilities.infra import cluster_resource
from utilities.storage import (
    create_dv,
    data_volume,
    data_volume_template_dict,
    is_snapshot_supported_by_sc,
    overhead_size_for_dv,
)
from utilities.virt import (
    VirtualMachineForTests,
    restart_vm_wait_for_running_vm,
    running_vm,
)


WINDOWS_CLONE_TIMEOUT = TIMEOUT_40MIN
FILESYSTEM = DataVolume.VolumeMode.FILE
BLOCK = DataVolume.VolumeMode.BLOCK
RWO = DataVolume.AccessMode.RWO


def verify_source_pvc_of_volume_snapshot(source_pvc_name, snapshot):
    for sample in TimeoutSampler(
        wait_timeout=20,
        sleep=1,
        func=lambda: snapshot.exists
        and snapshot.instance["spec"]["source"]["persistentVolumeClaimName"]
        == source_pvc_name,
    ):
        if sample:
            break


def create_vm_from_clone_dv_template(
    vm_name,
    dv_name,
    namespace_name,
    source_dv,
    client,
    volume_mode,
    storage_class,
    size=None,
):
    with cluster_resource(VirtualMachineForTests)(
        name=vm_name,
        namespace=namespace_name,
        os_flavor=OS_FLAVOR_CIRROS,
        client=client,
        memory_requests=Images.Cirros.DEFAULT_MEMORY_SIZE,
        data_volume_template=data_volume_template_dict(
            target_dv_name=dv_name,
            target_dv_namespace=namespace_name,
            source_dv=source_dv,
            volume_mode=volume_mode,
            size=size,
            storage_class=storage_class,
        ),
    ) as vm:
        running_vm(vm=vm, wait_for_interfaces=False)
        utils.check_disk_count_in_vm(vm=vm)


@pytest.fixture(scope="session")
def storage_class_with_block_volume_mode(available_storage_classes_names):
    yield get_storage_class_with_specified_volume_mode(
        volume_mode=BLOCK,
        sc_names=available_storage_classes_names,
    )


@pytest.fixture(scope="module")
def cirros_dv_with_filesystem_volume_mode(
    namespace,
    storage_class_with_filesystem_volume_mode,
):
    yield from create_cirros_dv(
        namespace=namespace.name,
        name="cirros-fs",
        storage_class=storage_class_with_filesystem_volume_mode,
        access_modes=RWO,
        volume_mode=FILESYSTEM,
    )


@pytest.fixture(scope="module")
def cirros_dv_with_block_volume_mode(
    namespace,
    storage_class_with_block_volume_mode,
):
    yield from create_cirros_dv(
        namespace=namespace.name,
        name="cirros-block",
        storage_class=storage_class_with_block_volume_mode,
        access_modes=RWO,
        volume_mode=BLOCK,
    )


@pytest.fixture()
def data_volume_snapshot_capable_storage_scope_function(
    request,
    namespace,
    storage_class_matrix_snapshot_matrix__function__,
    schedulable_nodes,
):
    yield from data_volume(
        request=request,
        namespace=namespace,
        storage_class_matrix=storage_class_matrix_snapshot_matrix__function__,
        schedulable_nodes=schedulable_nodes,
    )


@pytest.fixture(scope="module")
def skip_test_if_no_block_sc(storage_class_with_block_volume_mode):
    if not storage_class_with_block_volume_mode:
        pytest.skip("Skip the test: no Storage class with Block volume mode")


@pytest.mark.tier3
@pytest.mark.parametrize(
    "data_volume_multi_storage_scope_function",
    [
        pytest.param(
            {
                "dv_name": "dv-source",
                "image": f"{Images.Windows.DIR}/{Images.Windows.WIN19_IMG}",
                "dv_size": Images.Windows.DEFAULT_DV_SIZE,
            },
            marks=(pytest.mark.polarion("CNV-1892")),
        ),
    ],
    indirect=True,
)
def test_successful_clone_of_large_image(
    skip_upstream,
    admin_client,
    namespace,
    data_volume_multi_storage_scope_function,
):
    conditions = [
        DataVolume.Condition.Type.BOUND,
        DataVolume.Condition.Type.RUNNING,
        DataVolume.Condition.Type.READY,
    ]
    with create_dv(
        source="pvc",
        dv_name="dv-target",
        namespace=namespace.name,
        size=data_volume_multi_storage_scope_function.size,
        source_pvc=data_volume_multi_storage_scope_function.name,
        storage_class=data_volume_multi_storage_scope_function.storage_class,
    ) as cdv:
        if is_snapshot_supported_by_sc(sc_name=cdv.storage_class, client=admin_client):
            # Smart clone via snapshots does not hit this condition; no workers are spawned
            conditions.remove(DataVolume.Condition.Type.RUNNING)
        for condition in conditions:
            cdv.wait_for_condition(
                condition=condition,
                status=DataVolume.Condition.Status.TRUE,
                timeout=WINDOWS_CLONE_TIMEOUT,
            )


@pytest.mark.parametrize(
    "data_volume_multi_storage_scope_function",
    [
        pytest.param(
            {
                "dv_name": "dv-source",
                "image": f"{Images.Cirros.DIR}/{Images.Cirros.QCOW2_IMG}",
                "dv_size": Images.Cirros.DEFAULT_DV_SIZE,
            },
            marks=(
                pytest.mark.polarion("CNV-2148"),
                pytest.mark.post_upgrade(),
                pytest.mark.sno(),
            ),
        ),
    ],
    indirect=True,
)
def test_successful_vm_restart_with_cloned_dv(
    skip_upstream,
    namespace,
    data_volume_multi_storage_scope_function,
):
    with create_dv(
        source="pvc",
        dv_name="dv-target",
        namespace=namespace.name,
        size=data_volume_multi_storage_scope_function.size,
        source_pvc=data_volume_multi_storage_scope_function.name,
        storage_class=data_volume_multi_storage_scope_function.storage_class,
    ) as cdv:
        cdv.wait(timeout=TIMEOUT_10MIN)
        with utils.create_vm_from_dv(dv=cdv) as vm_dv:
            restart_vm_wait_for_running_vm(vm=vm_dv, wait_for_interfaces=False)
            utils.check_disk_count_in_vm(vm=vm_dv)


@pytest.mark.tier3
@pytest.mark.parametrize(
    ("data_volume_multi_storage_scope_function", "vm_params"),
    [
        pytest.param(
            {
                "dv_name": "dv-source",
                "source": "http",
                "image": f"{Images.Windows.RAW_DIR}/{Images.Windows.WIN19_RAW}",
                "dv_size": Images.Windows.DEFAULT_DV_SIZE,
            },
            {
                "vm_name": f"vm-win-{py_config['latest_windows_os_dict']['os_version']}",
                "template_labels": py_config["latest_windows_os_dict"][
                    "template_labels"
                ],
                "os_version": py_config["latest_windows_os_dict"]["os_version"],
                "username": py_config["windows_username"],
                "password": py_config["windows_password"],
                "ssh": True,
            },
            marks=pytest.mark.polarion("CNV-3638"),
        ),
    ],
    indirect=["data_volume_multi_storage_scope_function"],
)
def test_successful_vm_from_cloned_dv_windows(
    skip_upstream,
    unprivileged_client,
    data_volume_multi_storage_scope_function,
    vm_params,
    namespace,
):
    with create_dv(
        source="pvc",
        dv_name="dv-target",
        namespace=data_volume_multi_storage_scope_function.namespace,
        size=data_volume_multi_storage_scope_function.size,
        source_pvc=data_volume_multi_storage_scope_function.name,
        storage_class=data_volume_multi_storage_scope_function.storage_class,
    ) as cdv:
        cdv.wait(timeout=WINDOWS_CLONE_TIMEOUT)
        assert cdv.pvc.bound(), f"{cdv.name}'s PVC is not bound"
        utils.create_windows_vm_validate_guest_agent_info(
            dv=cdv,
            namespace=namespace,
            unprivileged_client=unprivileged_client,
            vm_params=vm_params,
        )


@pytest.mark.sno
@pytest.mark.parametrize(
    "data_volume_multi_storage_scope_function",
    [
        pytest.param(
            {
                "dv_name": "dv-source",
                "image": f"{Images.Cirros.DIR}/{Images.Cirros.QCOW2_IMG}",
                "dv_size": Images.Cirros.DEFAULT_DV_SIZE,
            },
            marks=(pytest.mark.polarion("CNV-4035")),
        )
    ],
    indirect=True,
)
def test_disk_image_after_clone(
    skip_block_volumemode_scope_function,
    namespace,
    data_volume_multi_storage_scope_function,
    unprivileged_client,
):
    with create_dv(
        source="pvc",
        dv_name="dv-cnv-4035",
        namespace=namespace.name,
        size=data_volume_multi_storage_scope_function.size,
        source_pvc=data_volume_multi_storage_scope_function.name,
        client=unprivileged_client,
        storage_class=data_volume_multi_storage_scope_function.storage_class,
    ) as cdv:
        cdv.wait()
        utils.create_vm_and_verify_image_permission(dv=cdv)


@pytest.mark.parametrize(
    "data_volume_snapshot_capable_storage_scope_function",
    [
        pytest.param(
            {
                "dv_name": "dv-source-cirros",
                "image": f"{Images.Cirros.DIR}/{Images.Cirros.QCOW2_IMG}",
                "dv_size": Images.Cirros.DEFAULT_DV_SIZE,
            },
            marks=(pytest.mark.polarion("CNV-3545")),
        ),
        pytest.param(
            {
                "dv_name": "dv-source-win",
                "image": f"{Images.Windows.RAW_DIR}/{Images.Windows.WIN19_RAW}",
                "dv_size": Images.Windows.DEFAULT_DV_SIZE,
            },
            marks=(pytest.mark.polarion("CNV-3552"), pytest.mark.tier3()),
        ),
    ],
    indirect=True,
)
def test_successful_snapshot_clone(
    skip_upstream,
    namespace,
    data_volume_snapshot_capable_storage_scope_function,
):
    with create_dv(
        source="pvc",
        dv_name="dv-target",
        namespace=namespace.name,
        size=data_volume_snapshot_capable_storage_scope_function.size,
        source_pvc=data_volume_snapshot_capable_storage_scope_function.name,
        storage_class=data_volume_snapshot_capable_storage_scope_function.storage_class,
    ) as cdv:
        cdv.wait_for_status(
            status=DataVolume.Status.SNAPSHOT_FOR_SMART_CLONE_IN_PROGRESS,
            timeout=TIMEOUT_5MIN,
        )
        snapshot = cluster_resource(VolumeSnapshot)(
            name=cdv.name, namespace=namespace.name
        )
        verify_source_pvc_of_volume_snapshot(
            source_pvc_name=data_volume_snapshot_capable_storage_scope_function.pvc.name,
            snapshot=snapshot,
        )
        cdv.wait()
        if (
            OS_FLAVOR_WINDOWS
            not in data_volume_snapshot_capable_storage_scope_function.url.split("/")[
                -1
            ]
        ):
            with utils.create_vm_from_dv(dv=cdv) as vm_dv:
                utils.check_disk_count_in_vm(vm=vm_dv)
        assert (
            cdv.pvc.instance.metadata.annotations.get("k8s.io/SmartCloneRequest")
            == "true"
        ), "Smart clone annotation does not exist on target PVC"
        snapshot.wait_deleted()


@pytest.mark.polarion("CNV-5607")
def test_clone_from_fs_to_block_using_dv_template(
    skip_test_if_no_filesystem_sc,
    skip_test_if_no_block_sc,
    unprivileged_client,
    namespace,
    cirros_dv_with_filesystem_volume_mode,
    storage_class_with_block_volume_mode,
):
    create_vm_from_clone_dv_template(
        vm_name="vm-5607",
        dv_name="dv-5607",
        namespace_name=namespace.name,
        source_dv=cirros_dv_with_filesystem_volume_mode,
        client=unprivileged_client,
        volume_mode=BLOCK,
        storage_class=storage_class_with_block_volume_mode,
    )


@pytest.mark.polarion("CNV-5608")
@pytest.mark.smoke()
def test_clone_from_block_to_fs_using_dv_template(
    skip_test_if_no_filesystem_sc,
    skip_test_if_no_block_sc,
    unprivileged_client,
    namespace,
    cirros_dv_with_block_volume_mode,
    storage_class_with_filesystem_volume_mode,
    default_fs_overhead,
):
    create_vm_from_clone_dv_template(
        vm_name="vm-5608",
        dv_name="dv-5608",
        namespace_name=namespace.name,
        source_dv=cirros_dv_with_block_volume_mode,
        client=unprivileged_client,
        volume_mode=FILESYSTEM,
        # add fs overhead and round up the result
        size=overhead_size_for_dv(
            image_size=int(cirros_dv_with_block_volume_mode.size[:-2]),
            overhead_value=default_fs_overhead,
        ),
        storage_class=storage_class_with_filesystem_volume_mode,
    )
