# -*- coding: utf-8 -*-

"""
VMExport tests
"""

import pytest
from kubernetes.client import ApiException
from ocp_resources.resource import Resource
from ocp_resources.virtual_machine_export import VirtualMachineExport
from ocp_utilities.infra import cluster_resource
from pytest_testconfig import config as py_config

from utilities.constants import Images


VIRTUALMACHINEEXPORTS = "virtualmachineexports"
ERROR_MSG_USER_CANNOT_CREATE_VM_EXPORT = (
    rf".*{VIRTUALMACHINEEXPORTS}.{Resource.ApiGroup.EXPORT_KUBEVIRT_IO} is forbidden: User.*cannot create resource"
    rf".*{VIRTUALMACHINEEXPORTS}.*in API group.*{Resource.ApiGroup.EXPORT_KUBEVIRT_IO}.*in the namespace"
)


@pytest.mark.parametrize(
    "namespace, data_volume_scope_function",
    [
        pytest.param(
            {"use_unprivileged_client": False},
            {
                "dv_name": "cirros-dv-9338",
                "image": f"{Images.Cirros.DIR}/{Images.Cirros.QCOW2_IMG}",
                "dv_size": Images.Cirros.DEFAULT_DV_SIZE,
                "storage_class": py_config["default_storage_class"],
            },
            marks=pytest.mark.polarion("CNV-9338"),
        )
    ],
    indirect=True,
)
def test_fail_to_vmexport_with_unprivileged_client_no_permissions(
    unprivileged_client,
    namespace,
    data_volume_scope_function,
):
    with pytest.raises(
        ApiException,
        match=ERROR_MSG_USER_CANNOT_CREATE_VM_EXPORT,
    ):
        with cluster_resource(VirtualMachineExport)(
            name="vmexport-unprivileged",
            namespace=data_volume_scope_function.namespace,
            client=unprivileged_client,
            source_api_group="",
            source_kind=VirtualMachineExport.SourceKind.PVC,
            source_name=data_volume_scope_function.name,
        ) as vmexport:
            assert not vmexport, "VMExport created by unprivileged client"
