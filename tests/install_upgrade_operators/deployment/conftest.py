import pytest
from ocp_resources.deployment import Deployment
from ocp_resources.storage_class import StorageClass

from tests.install_upgrade_operators.utils import get_deployment_by_name
from utilities.constants import HPP_POOL
from utilities.infra import cluster_resource, get_deployments


@pytest.fixture()
def deployment_by_name(request, admin_client, hco_namespace):
    """
    Gets a deployment object by name.
    """
    deployment_name = request.param["deployment_name"]
    deployment_by_name = get_deployment_by_name(
        deployment_name=deployment_name,
        admin_client=admin_client,
        namespace_name=hco_namespace.name,
    )
    assert deployment_by_name.exists, f"Deployment {deployment_name} not found."
    yield deployment_by_name


@pytest.fixture(scope="module")
def cnv_deployments_excluding_hpp_pool(admin_client, hco_namespace):
    return [
        deployment
        for deployment in get_deployments(
            admin_client=admin_client, namespace=hco_namespace.name
        )
        if not deployment.name.startswith(HPP_POOL)
    ]


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


@pytest.fixture()
def skip_on_hpp_pool(cnv_deployment_matrix__function__):
    if cnv_deployment_matrix__function__ == HPP_POOL:
        pytest.skip(f"Priority class test is not valid for {HPP_POOL} deployment")
