import logging

import pytest
from pytest_testconfig import config as py_config

from tests.compute.utils import (
    generate_attached_rhsm_secret_dict,
    generate_rhsm_cloud_init_data,
)
from tests.compute.virt.longevity_tests.constants import (
    LINUX_OS_PREFIX,
    WINDOWS_OS_PREFIX,
)
from tests.compute.virt.longevity_tests.utils import (
    create_containerdisk_vms,
    create_dv_vms,
    wait_vms_booted_and_start_processes,
)
from utilities.constants import StorageClassNames
from utilities.storage import create_or_update_data_source, data_volume


LOGGER = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def vm_deploys():
    deploys = int(py_config["vm_deploys"])
    if deploys < 1:
        raise ValueError("VM deploys value is less then 1!")
    return deploys


@pytest.fixture()
def vm_request(request):
    """
    Fixture is used to store VM related params that are common for all test VMs.
    This is needed to not pass params via pytest.mark.parametrize to each VM fixture separately
    """
    return request


@pytest.fixture()
def nfs_vms(
    vm_deploys,
    vm_request,
    namespace,
    unprivileged_client,
    golden_image_data_source_nfs,
):
    LOGGER.info("Deploying VMs with NFS disk")
    yield from create_dv_vms(
        vm_deploys=vm_deploys,
        request=vm_request,
        client=unprivileged_client,
        namespace=namespace,
        name="nfsdisk",
        data_source=golden_image_data_source_nfs,
    )


@pytest.fixture()
def ocs_vms(
    vm_deploys,
    vm_request,
    namespace,
    unprivileged_client,
    golden_image_data_source_ocs,
):
    LOGGER.info("Deploying VMs with OCS disk")
    yield from create_dv_vms(
        vm_deploys=vm_deploys,
        request=vm_request,
        client=unprivileged_client,
        namespace=namespace,
        name="ocsdisk",
        data_source=golden_image_data_source_ocs,
    )


@pytest.fixture()
def secret_vms(
    vm_deploys,
    vm_request,
    namespace,
    unprivileged_client,
    golden_image_data_source_ocs,
    rhsm_created_secret,
):
    LOGGER.info("Deploying VMs with secret")
    yield from create_dv_vms(
        vm_deploys=vm_deploys,
        request=vm_request,
        client=unprivileged_client,
        namespace=namespace,
        name="secret",
        data_source=golden_image_data_source_ocs,
        cloud_init_data=generate_rhsm_cloud_init_data(),
        attached_secret=generate_attached_rhsm_secret_dict(),
    )


@pytest.fixture()
def container_disk_vms(vm_deploys, vm_request, namespace, unprivileged_client):
    LOGGER.info("Deploying VM with container disk")
    yield from create_containerdisk_vms(
        vm_deploys=vm_deploys,
        request=vm_request,
        client=unprivileged_client,
        namespace=namespace,
        name="containerdisk",
    )


@pytest.fixture()
def linux_vms_with_pids(
    cluster_cpu_model_scope_module, nfs_vms, ocs_vms, secret_vms, container_disk_vms
):
    vms_list = nfs_vms + ocs_vms + secret_vms + container_disk_vms
    return wait_vms_booted_and_start_processes(
        vms_list=vms_list, os_type=LINUX_OS_PREFIX
    )


@pytest.fixture()
def windows_vms_with_pids(cluster_cpu_model_scope_module, nfs_vms, ocs_vms):
    vms_list = nfs_vms + ocs_vms
    return wait_vms_booted_and_start_processes(
        vms_list=vms_list, os_type=WINDOWS_OS_PREFIX
    )


@pytest.fixture()
def golden_image_data_volume_ocs(request, admin_client, golden_images_namespace):
    yield from data_volume(
        request=request,
        namespace=golden_images_namespace,
        storage_class=StorageClassNames.CEPH_RBD,
        check_dv_exists=True,
        admin_client=admin_client,
    )


@pytest.fixture()
def golden_image_data_source_ocs(admin_client, golden_image_data_volume_ocs):
    yield from create_or_update_data_source(
        admin_client=admin_client, dv=golden_image_data_volume_ocs
    )


@pytest.fixture()
def golden_image_data_volume_nfs(request, admin_client, golden_images_namespace):
    yield from data_volume(
        request=request,
        namespace=golden_images_namespace,
        storage_class=StorageClassNames.NFS,
        check_dv_exists=True,
        admin_client=admin_client,
    )


@pytest.fixture()
def golden_image_data_source_nfs(admin_client, golden_image_data_volume_nfs):
    yield from create_or_update_data_source(
        admin_client=admin_client, dv=golden_image_data_volume_nfs
    )
