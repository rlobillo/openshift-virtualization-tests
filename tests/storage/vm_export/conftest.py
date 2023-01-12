# -*- coding: utf-8 -*-

"""
Pytest conftest file for CNV VMExport tests
"""
import pytest
from ocp_resources.configmap import ConfigMap
from ocp_resources.datavolume import DataVolume
from ocp_resources.secret import Secret
from ocp_resources.virtual_machine_export import VirtualMachineExport
from ocp_resources.virtual_machine_snapshot import VirtualMachineSnapshot
from ocp_utilities.infra import cluster_resource

from tests.storage.vm_export.utils import (
    CNV_EXPORT_TOKEN,
    FROM_VMEXPORT_SNAPSHOT,
    VMEXPORT_FROM_SNAPSHOT,
    get_vmexport_external_url,
)
from utilities.constants import OS_FLAVOR_CIRROS, Images
from utilities.infra import create_ns
from utilities.virt import VirtualMachineForTests


@pytest.fixture(scope="module")
def vmexport_secret_token(namespace):
    with cluster_resource(Secret)(
        name="virt-export-token",
        namespace=namespace.name,
        string_data={"token": CNV_EXPORT_TOKEN},
    ) as secret:
        yield secret


@pytest.fixture()
def vmexport_from_vmsnapshot(
    admin_client, namespace, snapshots_with_content, vmexport_secret_token
):
    with cluster_resource(VirtualMachineExport)(
        name=VMEXPORT_FROM_SNAPSHOT,
        namespace=namespace.name,
        client=admin_client,
        source_api_group=VirtualMachineSnapshot.api_group,
        source_kind=VirtualMachineExport.SourceKind.VM_SNAPSHOT,
        source_name=snapshots_with_content[0].name,
        token_secret_ref=vmexport_secret_token.name,
    ) as vmexport:
        vmexport.wait_for_status(status=VirtualMachineExport.Status.READY)
        yield vmexport


@pytest.fixture(scope="module")
def namespace_vmexport_target():
    yield from create_ns(name="vm-export-test-target")


@pytest.fixture()
def configmap_with_vmexport_external_cert_vmsnapshot(
    namespace_vmexport_target, vmexport_from_vmsnapshot
):
    with cluster_resource(ConfigMap)(
        name="router-cert",
        namespace=namespace_vmexport_target.name,
        data={
            "router-cert": vmexport_from_vmsnapshot.instance.status.links.external.cert
        },
    ) as configmap:
        yield configmap


@pytest.fixture()
def secret_headers(namespace_vmexport_target):
    with cluster_resource(Secret)(
        name="secret-headers",
        namespace=namespace_vmexport_target.name,
        string_data={"token": f"x-kubevirt-export-token:{CNV_EXPORT_TOKEN}"},
    ) as secret:
        yield secret


@pytest.fixture()
def cirros_dv_for_vmexport_snapshot_target_dict(
    namespace_vmexport_target,
    vmexport_from_vmsnapshot,
    configmap_with_vmexport_external_cert_vmsnapshot,
    secret_headers,
    storage_class_matrix_snapshot_matrix__module__,
):
    dv = cluster_resource(DataVolume)(
        api_name="storage",
        name=f"dv-{FROM_VMEXPORT_SNAPSHOT}",
        namespace=namespace_vmexport_target.name,
        source="http",
        cert_configmap=configmap_with_vmexport_external_cert_vmsnapshot.name,
        url=get_vmexport_external_url(vmexport=vmexport_from_vmsnapshot),
        storage_class=[*storage_class_matrix_snapshot_matrix__module__][0],
        size=Images.Cirros.DEFAULT_DV_SIZE,
    )
    dv.to_dict()
    dv.res["spec"]["source"]["http"].setdefault("secretExtraHeaders", []).append(
        secret_headers.name
    )
    return dv.res


@pytest.fixture()
def vm_from_vmexport(admin_client, cirros_dv_for_vmexport_snapshot_target_dict):
    dv_metadata = cirros_dv_for_vmexport_snapshot_target_dict["metadata"]
    with cluster_resource(VirtualMachineForTests)(
        client=admin_client,
        name=f"vm-{FROM_VMEXPORT_SNAPSHOT}",
        namespace=dv_metadata["namespace"],
        os_flavor=OS_FLAVOR_CIRROS,
        memory_requests=Images.Cirros.DEFAULT_MEMORY_SIZE,
        data_volume_template={
            "metadata": dv_metadata,
            "spec": cirros_dv_for_vmexport_snapshot_target_dict["spec"],
        },
    ) as vm:
        yield vm
