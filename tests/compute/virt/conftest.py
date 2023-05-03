import logging

import pytest
from ocp_resources.migration_policy import MigrationPolicy
from ocp_resources.persistent_volume_claim import PersistentVolumeClaim
from ocp_resources.pod import Pod
from pytest_testconfig import py_config

from tests.compute.utils import generate_rhsm_secret
from tests.compute.virt.constants import MIGRATION_POLICY_VM_LABEL
from tests.compute.virt.utils import append_feature_gate_to_hco
from utilities.constants import INTEL
from utilities.infra import cluster_resource, get_daemonset_by_name
from utilities.storage import create_or_update_data_source
from utilities.virt import vm_instance_from_template


LOGGER = logging.getLogger(__name__)


@pytest.fixture()
def skip_rwo_default_access_mode():
    if py_config["default_access_mode"] == PersistentVolumeClaim.AccessMode.RWO:
        pytest.skip("Skipping, default storage access mode is RWO")


@pytest.fixture()
def enabled_featuregate_scope_function(
    request,
    hyperconverged_resource_scope_function,
    kubevirt_feature_gates,
    admin_client,
    hco_namespace,
):
    feature_gate = request.param
    kubevirt_feature_gates.append(feature_gate)
    with append_feature_gate_to_hco(
        feature_gate=kubevirt_feature_gates,
        resource=hyperconverged_resource_scope_function,
        client=admin_client,
        namespace=hco_namespace,
    ):
        yield


@pytest.fixture(scope="class")
def golden_image_dv_scope_module_data_source_scope_class(
    admin_client, golden_image_data_volume_scope_module
):
    yield from create_or_update_data_source(
        admin_client=admin_client, dv=golden_image_data_volume_scope_module
    )


@pytest.fixture(scope="module")
def virt_handler_daemonset_scope_module(hco_namespace, admin_client):
    return get_daemonset_by_name(
        admin_client=admin_client,
        daemonset_name="virt-handler",
        namespace_name=hco_namespace.name,
    )


@pytest.fixture(scope="module")
def virt_pods(request, admin_client, hco_namespace):
    podprefix = request.param
    pods_list = list(
        Pod.get(
            admin_client,
            namespace=hco_namespace.name,
            label_selector=f"kubevirt.io={podprefix}",
        )
    )
    assert pods_list, f"No pods found for {podprefix}"
    yield pods_list


@pytest.fixture()
def rhsm_created_secret(namespace):
    yield from generate_rhsm_secret(namespace=namespace)


@pytest.fixture()
def migration_policy_with_bandwidth():
    with cluster_resource(MigrationPolicy)(
        name="migration-policy",
        bandwidth_per_migration="128Ki",
        vmi_selector=MIGRATION_POLICY_VM_LABEL,
    ) as mp:
        yield mp


@pytest.fixture()
def vm_with_memory_load(
    request,
    unprivileged_client,
    namespace,
    golden_image_data_source_scope_function,
    nodes_common_cpu_model,
    nodes_cpu_architecture,
):
    cpu_features = "vmx" if nodes_cpu_architecture == INTEL else "svm"
    with vm_instance_from_template(
        request=request,
        unprivileged_client=unprivileged_client,
        namespace=namespace,
        data_source=golden_image_data_source_scope_function,
        vm_cpu_model=nodes_common_cpu_model
        if nodes_cpu_architecture == INTEL
        else None,
        vm_cpu_flags={"features": [{"name": cpu_features, "policy": "require"}]},
    ) as vm:
        yield vm
