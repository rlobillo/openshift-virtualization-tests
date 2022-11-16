import copy

import pytest
from ocp_utilities.infra import cluster_resource

from tests.infrastructure.instance_types.utils import (
    VirtualMachineClusterInstanceTypeForTest,
    VirtualMachineClusterPreferenceForTest,
    VirtualMachineInstanceTypeForTest,
    VirtualMachinePreferenceForTest,
)


@pytest.fixture(scope="class")
def instance_type_for_test(namespace, common_instance_type_param_dict):
    instance_type_param_dict = copy.deepcopy(common_instance_type_param_dict)
    instance_type_param_dict["namespace"] = namespace.name
    return cluster_resource(VirtualMachineInstanceTypeForTest)(
        **instance_type_param_dict
    )


@pytest.fixture(scope="class")
def cluster_instance_type_for_test(common_instance_type_param_dict):
    return cluster_resource(VirtualMachineClusterInstanceTypeForTest)(
        **common_instance_type_param_dict
    )


@pytest.fixture(scope="class")
def common_instance_type_param_dict(request):
    return {
        "name": request.param["name"],
        "cpu_cores": request.param.get("cpu_cores"),
        "memory_requests": request.param.get("memory_requests"),
        "dedicated_cpu_placement": request.param.get("dedicated_cpu_placement"),
        "cpu_model": request.param.get("cpu_model"),
        "cpu_isolate_emulator_thread": request.param.get("cpu_isolate_emulator_thread"),
        "cpu_numa": request.param.get("cpu_numa"),
        "cpu_realtime": request.param.get("cpu_realtime"),
        "gpus_list": request.param.get("gpus_list"),
        "host_devices_list": request.param.get("host_devices_list"),
        "io_thread_policy": request.param.get("io_thread_policy"),
        "memory_huge_pages": request.param.get("memory_huge_pages"),
    }


@pytest.fixture(scope="class")
def vm_preference_for_test(namespace, common_vm_preference_param_dict):
    vm_preference_param_dict = copy.deepcopy(common_vm_preference_param_dict)
    vm_preference_param_dict["namespace"] = namespace.name
    return cluster_resource(VirtualMachinePreferenceForTest)(**vm_preference_param_dict)


@pytest.fixture(scope="class")
def vm_cluster_preference_for_test(common_vm_preference_param_dict):
    return cluster_resource(VirtualMachineClusterPreferenceForTest)(
        **common_vm_preference_param_dict
    )


@pytest.fixture(scope="class")
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
