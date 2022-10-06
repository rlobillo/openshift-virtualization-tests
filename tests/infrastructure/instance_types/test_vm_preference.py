import copy

import pytest
from ocp_utilities.infra import cluster_resource

from tests.infrastructure.instance_types.constants import ALL_OPTIONS_VM_PREFERENCE_SPEC
from tests.infrastructure.instance_types.utils import (
    VirtualMachineClusterPreferenceForTest,
    VirtualMachinePreferenceForTest,
)


@pytest.fixture()
def vm_preference_for_test(namespace, common_vm_preference_param_dict):
    vm_preference_param_dict = copy.deepcopy(common_vm_preference_param_dict)
    vm_preference_param_dict["namespace"] = namespace.name
    return cluster_resource(VirtualMachinePreferenceForTest)(**vm_preference_param_dict)


@pytest.fixture()
def vm_cluster_preference_for_test(common_vm_preference_param_dict):
    return cluster_resource(VirtualMachineClusterPreferenceForTest)(
        **common_vm_preference_param_dict
    )


@pytest.fixture()
def common_vm_preference_param_dict(request):
    return {
        "name": request.param["name"],
        "client": request.param.get("client"),
        "teardown": request.param.get("teardown", True),
        "yaml_file": request.param.get("yaml_file"),
        "clock_timezone": request.param.get("clock_timezone"),
        "clock_utc_seconds_offset": request.param.get("clock_utc_seconds_offset"),
        "clock_preferred_timer": request.param.get("clock_preferred_timer"),
        "cpu_topology": request.param.get("cpu_topology"),
        "devices": request.param.get("devices"),
        "features": request.param.get("features"),
        "firmware": request.param.get("firmware"),
        "machine": request.param.get("machine"),
    }


class TestVmPreference:
    @pytest.mark.parametrize(
        "common_vm_preference_param_dict",
        [
            pytest.param(
                {
                    "name": "basic-preference",
                },
            ),
            pytest.param(
                {
                    **{"name": "all-options-vm-preference"},
                    **ALL_OPTIONS_VM_PREFERENCE_SPEC,
                },
            ),
        ],
        indirect=True,
    )
    @pytest.mark.polarion("CNV-9084")
    def test_create_preference(self, vm_preference_for_test):
        with vm_preference_for_test as vm_preference:
            assert vm_preference.exists


class TestVmClusterPreference:
    @pytest.mark.parametrize(
        "common_vm_preference_param_dict",
        [
            pytest.param(
                {
                    "name": "basic-cluster-preference",
                },
            ),
            pytest.param(
                {
                    **{"name": "all-options-vm-cluster-preference"},
                    **ALL_OPTIONS_VM_PREFERENCE_SPEC,
                },
            ),
        ],
        indirect=True,
    )
    @pytest.mark.polarion("CNV-9335")
    def test_create_cluster_preference(self, vm_cluster_preference_for_test):
        with vm_cluster_preference_for_test as vm_cluster_preference:
            assert vm_cluster_preference.exists
