import importlib
import logging
import pkgutil

import pytest
from ocp_resources.cdi import CDI
from ocp_resources.deployment import Deployment
from ocp_resources.kubevirt import KubeVirt
from ocp_resources.network_addons_config import NetworkAddonsConfig
from ocp_resources.storage_class import StorageClass
from openshift.dynamic.exceptions import ResourceNotFoundError
from pytest_testconfig import py_config

from tests.install_upgrade_operators.utils import (
    get_deployment_by_name,
    get_network_addon_config,
    get_resource_from_module_name,
)
from utilities.constants import HPP_POOL
from utilities.hco import ResourceEditorValidateHCOReconcile, get_hco_version
from utilities.infra import cluster_resource
from utilities.operator import (
    disable_default_sources_in_operatorhub,
    get_machine_config_pool_by_name,
)
from utilities.storage import get_hyperconverged_cdi
from utilities.virt import get_hyperconverged_kubevirt


LOGGER = logging.getLogger(__name__)


@pytest.fixture()
def skip_on_hpp_pool(cnv_deployment_matrix__function__):
    if cnv_deployment_matrix__function__ == HPP_POOL:
        pytest.skip(f"Priority class test is not valid for {HPP_POOL} deployment")


@pytest.fixture()
def cnv_deployment_by_name(
    admin_client,
    hco_namespace,
    cnv_deployment_matrix__function__,
):
    if cnv_deployment_matrix__function__ == HPP_POOL:
        hpp_pool_deployments = list(
            cluster_resource(Deployment).get(
                dyn_client=admin_client,
                namespace=hco_namespace.name,
                label_selector=f"{StorageClass.Provisioner.HOSTPATH_CSI}/storagePool=hpp-csi-pvc-block-hpp",
            )
        )
        if not hpp_pool_deployments:
            pytest.skip("HPP pool deployment not found on this cluster")
        return hpp_pool_deployments[0]

    return get_deployment_by_name(
        admin_client=admin_client,
        namespace_name=hco_namespace.name,
        deployment_name=cnv_deployment_matrix__function__,
    )


@pytest.fixture(scope="session")
def ocp_resources_submodule_list():
    """
    Gets the list of submodules in ocp_resources. This list is needed to make get and patch call to the right resource
    """
    path = importlib.util.find_spec("ocp_resources").submodule_search_locations
    return [module.name for module in pkgutil.iter_modules(path)]


@pytest.fixture(scope="session")
def cnv_registry_source(cnv_source):
    return py_config["cnv_registry_sources"][cnv_source]


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
    admin_client, is_production_source, installing_cnv
):
    if installing_cnv and is_production_source:
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


@pytest.fixture()
def machine_config_pools_conditions(machine_config_pools):
    return {mcp.name: mcp.instance.status.conditions for mcp in machine_config_pools}


@pytest.fixture()
def ocp_resource_by_name(
    admin_client, ocp_resources_submodule_list, related_object_from_hco_status
):
    return get_resource_from_module_name(
        related_obj=related_object_from_hco_status,
        ocp_resources_submodule_list=ocp_resources_submodule_list,
        admin_client=admin_client,
    )


@pytest.fixture()
def related_object_from_hco_status(
    hco_status_related_objects, cnv_related_object_matrix__function__
):
    LOGGER.info(cnv_related_object_matrix__function__)
    kind_name = list(cnv_related_object_matrix__function__.values())[0]
    related_object_name = list(cnv_related_object_matrix__function__.keys())[0]
    LOGGER.info(f"Looking for related object {related_object_name}, kind {kind_name}")
    for obj in hco_status_related_objects:
        if obj.name == related_object_name and obj.kind == kind_name:
            return obj
    raise ResourceNotFoundError(
        f"Related object {related_object_name}, kind {kind_name} not found in "
        f"hco.status.relatedObjects: {hco_status_related_objects}"
    )
