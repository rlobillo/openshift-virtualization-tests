import pytest
from ocp_resources.cdi import CDI
from ocp_resources.kubevirt import KubeVirt
from ocp_resources.network_addons_config import NetworkAddonsConfig
from pytest_testconfig import py_config

from tests.install_upgrade_operators.utils import get_network_addon_config
from utilities.hco import ResourceEditorValidateHCOReconcile, get_hco_version
from utilities.operator import (
    disable_default_sources_in_operatorhub,
    get_machine_config_pool_by_name,
)
from utilities.storage import get_hyperconverged_cdi
from utilities.virt import get_hyperconverged_kubevirt


@pytest.fixture(scope="session")
def cnv_source(pytestconfig):
    return pytestconfig.option.cnv_source


@pytest.fixture(scope="session")
def cnv_registry_source(cnv_source):
    return py_config["cnv_registry_sources"][cnv_source]


@pytest.fixture(scope="session")
def is_upgrade_from_production_source(cnv_source):
    return cnv_source == "production"


@pytest.fixture(scope="session")
def is_upgrade_from_stage_source(cnv_source):
    return cnv_source == "stage"


@pytest.fixture()
def kubevirt_resource(admin_client, hco_namespace):
    return get_hyperconverged_kubevirt(
        admin_client=admin_client, hco_namespace=hco_namespace
    )


@pytest.fixture()
def cdi_resource_scope_function(admin_client):
    return get_hyperconverged_cdi(admin_client=admin_client)


@pytest.fixture()
def cnao_resource(admin_client):
    return get_network_addon_config(admin_client=admin_client)


@pytest.fixture()
def cnao_spec(cnao_resource):
    return cnao_resource.instance.to_dict()["spec"]


@pytest.fixture()
def updated_hco_cr(
    request, hyperconverged_resource_scope_function, admin_client, hco_namespace
):
    """
    This fixture updates HCO CR with values specified via request.param
    """
    with ResourceEditorValidateHCOReconcile(
        patches={hyperconverged_resource_scope_function: request.param["patch"]},
        list_resource_reconcile=request.param.get(
            "list_resource_reconcile", [NetworkAddonsConfig, CDI, KubeVirt]
        ),
        wait_for_reconcile_post_update=True,
    ):
        yield


@pytest.fixture()
def updated_kubevirt_cr(request, kubevirt_resource, admin_client, hco_namespace):
    """
    Attempts to update kubevirt CR
    """
    with ResourceEditorValidateHCOReconcile(
        patches={kubevirt_resource: request.param["patch"]},
        list_resource_reconcile=[KubeVirt],
        wait_for_reconcile_post_update=True,
    ):
        yield


@pytest.fixture()
def ssp_cr_spec(ssp_resource_scope_function):
    return ssp_resource_scope_function.instance.to_dict()["spec"]


@pytest.fixture(scope="module")
def hco_spec_scope_module(hyperconverged_resource_scope_module):
    return hyperconverged_resource_scope_module.instance.to_dict()["spec"]


@pytest.fixture(scope="module")
def hco_status_related_objects(hyperconverged_resource_scope_module):
    """
    Gets HCO.status.relatedObjects list
    """
    return hyperconverged_resource_scope_module.instance.status.relatedObjects


@pytest.fixture(scope="class")
def hco_version_scope_class(admin_client, hco_namespace):
    return get_hco_version(client=admin_client, hco_ns_name=hco_namespace.name)


@pytest.fixture()
def disabled_default_sources_in_operatorhub(
    admin_client, is_upgrade_from_production_source
):
    if is_upgrade_from_production_source:
        yield
    else:
        with disable_default_sources_in_operatorhub(admin_client=admin_client):
            yield


@pytest.fixture(scope="session")
def cnv_image_url(pytestconfig):
    return pytestconfig.option.cnv_image


@pytest.fixture(scope="session")
def machine_config_pools():
    return [
        get_machine_config_pool_by_name(mcp_name="master"),
        get_machine_config_pool_by_name(mcp_name="worker"),
    ]
