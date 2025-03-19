from contextlib import contextmanager

import pytest

from utilities.hco import update_hco_annotations
from utilities.virt import (
    vm_instance_from_template,
    wait_for_kv_stabilize,
    wait_for_updated_kv_value,
)


@contextmanager
def update_cluster_cpu_model(admin_client, hco_namespace, hco_resource, cpu_model):
    with update_hco_annotations(
        resource=hco_resource,
        path="cpuModel",
        value=cpu_model,
    ):
        wait_for_updated_kv_value(
            admin_client=admin_client,
            hco_namespace=hco_namespace,
            path=["cpuModel"],
            value=cpu_model,
            timeout=30,
        )
        yield


@pytest.fixture(scope="module")
def cluster_cpu_model_scope_module(
    admin_client,
    hco_namespace,
    hyperconverged_resource_scope_module,
    nodes_common_cpu_model,
):
    with update_cluster_cpu_model(
        admin_client=admin_client,
        hco_namespace=hco_namespace,
        hco_resource=hyperconverged_resource_scope_module,
        cpu_model=nodes_common_cpu_model,
    ):
        yield
    wait_for_kv_stabilize(admin_client=admin_client, hco_namespace=hco_namespace)


@pytest.fixture(scope="class")
def cluster_cpu_model_scope_class(
    admin_client,
    hco_namespace,
    hyperconverged_resource_scope_class,
    nodes_common_cpu_model,
):
    with update_cluster_cpu_model(
        admin_client=admin_client,
        hco_namespace=hco_namespace,
        hco_resource=hyperconverged_resource_scope_class,
        cpu_model=nodes_common_cpu_model,
    ):
        yield
    wait_for_kv_stabilize(admin_client=admin_client, hco_namespace=hco_namespace)


@pytest.fixture()
def cluster_cpu_model_scope_function(
    admin_client,
    hco_namespace,
    hyperconverged_resource_scope_function,
    nodes_common_cpu_model,
):
    with update_cluster_cpu_model(
        admin_client=admin_client,
        hco_namespace=hco_namespace,
        hco_resource=hyperconverged_resource_scope_function,
        cpu_model=nodes_common_cpu_model,
    ):
        yield
    wait_for_kv_stabilize(admin_client=admin_client, hco_namespace=hco_namespace)


@pytest.fixture()
def vm_from_template_scope_function(
    request,
    unprivileged_client,
    namespace,
    golden_image_data_source_scope_function,
):
    with vm_instance_from_template(
        request=request,
        unprivileged_client=unprivileged_client,
        namespace=namespace,
        data_source=golden_image_data_source_scope_function,
    ) as vm_from_template:
        yield vm_from_template


@pytest.fixture()
def vm_from_template_with_existing_dv(
    request,
    unprivileged_client,
    namespace,
    data_volume_scope_function,
):
    """create VM from template using an existing DV (and not a golden image)"""
    with vm_instance_from_template(
        request=request,
        unprivileged_client=unprivileged_client,
        namespace=namespace,
        existing_data_volume=data_volume_scope_function,
    ) as vm:
        yield vm


@pytest.fixture(scope="module")
def machine_type_from_kubevirt_config(kubevirt_config_scope_module):
    """Extract machine type default from kubevirt CR."""
    return kubevirt_config_scope_module["machineType"]
