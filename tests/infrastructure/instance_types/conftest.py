import pytest
from ocp_utilities.infra import cluster_resource

from tests.infrastructure.instance_types.utils import (
    VirtualMachineClusterInstanceTypeForTest,
    VirtualMachineClusterPreferenceForTest,
)


@pytest.fixture(scope="class")
def cluster_instance_type_for_test_scope_class(common_instance_type_param_dict):
    return cluster_resource(VirtualMachineClusterInstanceTypeForTest)(
        **common_instance_type_param_dict
    )


@pytest.fixture(scope="class")
def vm_cluster_preference_for_test(common_vm_preference_param_dict):
    return cluster_resource(VirtualMachineClusterPreferenceForTest)(
        **common_vm_preference_param_dict
    )
