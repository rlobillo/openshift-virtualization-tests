import logging

import pytest
from ocp_resources.api_server import APIServer
from ocp_resources.cdi import CDI
from ocp_resources.kubevirt import KubeVirt
from ocp_resources.network_addons_config import NetworkAddonsConfig
from ocp_resources.resource import ResourceEditor
from ocp_resources.service import Service
from ocp_resources.ssp import SSP
from ocp_utilities.infra import cluster_resource
from openshift.dynamic.exceptions import ResourceNotFoundError

from tests.install_upgrade_operators.constants import KEY_PATH_SEPARATOR
from tests.install_upgrade_operators.crypto_policy.constants import (
    CRYPTO_POLICY_SPEC_DICT,
    KEY_NAME_STR,
    MANAGED_CRS_LIST,
    RESOURCE_NAME_STR,
    RESOURCE_NAMESPACE_STR,
    RESOURCE_TYPE_STR,
)
from tests.install_upgrade_operators.crypto_policy.utils import (
    get_resource_crypto_policy,
    wait_for_cluster_operator_stabilize,
)
from utilities.constants import (
    CDI_KUBEVIRT_HYPERCONVERGED,
    CLUSTER_RESOURCE_NAME,
    KUBEVIRT_HCO_NAME,
    SSP_KUBEVIRT_HYPERCONVERGED,
    TLS_SECURITY_PROFILE,
)
from utilities.hco import wait_for_hco_conditions
from utilities.infra import MissingResourceException


LOGGER = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def resources_dict(hco_namespace):
    return {
        KubeVirt: {
            RESOURCE_NAME_STR: KUBEVIRT_HCO_NAME,
            RESOURCE_NAMESPACE_STR: hco_namespace.name,
            KEY_NAME_STR: f"configuration{KEY_PATH_SEPARATOR}{TLS_SECURITY_PROFILE}",
        },
        SSP: {
            RESOURCE_NAME_STR: SSP_KUBEVIRT_HYPERCONVERGED,
            RESOURCE_NAMESPACE_STR: hco_namespace.name,
            KEY_NAME_STR: TLS_SECURITY_PROFILE,
        },
        CDI: {
            RESOURCE_NAME_STR: CDI_KUBEVIRT_HYPERCONVERGED,
            KEY_NAME_STR: f"config{KEY_PATH_SEPARATOR}{TLS_SECURITY_PROFILE}",
        },
        NetworkAddonsConfig: {
            RESOURCE_NAME_STR: CLUSTER_RESOURCE_NAME,
            RESOURCE_NAMESPACE_STR: None,
            KEY_NAME_STR: TLS_SECURITY_PROFILE,
        },
    }


@pytest.fixture()
def resource_crypto_policy_settings(request, admin_client):
    yield get_resource_crypto_policy(
        admin_client=admin_client,
        resource=request.param.get(RESOURCE_TYPE_STR),
        name=request.param.get(RESOURCE_NAME_STR),
        namespace=request.param.get(RESOURCE_NAMESPACE_STR),
        key_name=request.param.get(KEY_NAME_STR),
    )


@pytest.fixture(scope="module")
def api_server(admin_client):
    api_server = cluster_resource(APIServer)(
        client=admin_client, name=CLUSTER_RESOURCE_NAME
    )
    if api_server.exists:
        return api_server
    raise ResourceNotFoundError(
        f"{api_server.kind}: {CLUSTER_RESOURCE_NAME} not found."
    )


@pytest.fixture()
def updated_api_server_crypto_policy(
    admin_client, hco_namespace, cnv_crypto_policy_matrix__function__, api_server
):
    tls_security_spec = CRYPTO_POLICY_SPEC_DICT.get(
        cnv_crypto_policy_matrix__function__
    )
    assert (
        tls_security_spec
    ), f"{cnv_crypto_policy_matrix__function__} needs to be added to {CRYPTO_POLICY_SPEC_DICT}"
    with ResourceEditor(
        patches={api_server: {"spec": {TLS_SECURITY_PROFILE: tls_security_spec}}},
    ):
        yield
    wait_for_cluster_operator_stabilize(admin_client=admin_client)
    wait_for_hco_conditions(
        admin_client=admin_client,
        hco_namespace=hco_namespace,
        list_dependent_crs_to_check=MANAGED_CRS_LIST,
    )


@pytest.fixture(scope="session")
def services_to_check_connectivity(hco_namespace):
    services_list = []
    missing_services = []
    for service_name in [
        "virt-api",
        "ssp-operator-service",
        "ssp-operator-metrics",
        "virt-template-validator",
        "kubemacpool-service",
        "cdi-api",
    ]:
        service = cluster_resource(Service)(
            name=service_name, namespace=hco_namespace.name
        )
        services_list.append(service) if service.exists else missing_services.append(
            service_name
        )

    if missing_services:
        raise MissingResourceException(f"Services: {missing_services}.")

    return services_list
