import logging

import pytest
from ocp_resources.cdi import CDI
from ocp_resources.kubevirt import KubeVirt
from ocp_resources.network_addons_config import NetworkAddonsConfig
from ocp_resources.ssp import SSP
from pytest_testconfig import config as py_config

from tests.install_upgrade_operators.constants import KEY_PATH_SEPARATOR
from tests.install_upgrade_operators.crypto_policy.constants import (
    KEY_NAME_STR,
    MIN_TLS_VERSIONS,
    RESOURCE_NAME_STR,
    RESOURCE_NAMESPACE_STR,
    TLS_CUSTOM_CIPHERS,
    TLS_SECURITY_PROFILE,
)
from tests.install_upgrade_operators.crypto_policy.utils import (
    assert_crypto_policy_propagated_to_components,
    assert_no_crypto_policy_in_hco,
    assert_tls_ciphers_blocked,
    assert_tls_version_connection,
)
from utilities.constants import (
    CDI_KUBEVIRT_HYPERCONVERGED,
    CLUSTER_RESOURCE_NAME,
    KUBEVIRT_HCO_NAME,
    SSP_KUBEVIRT_HYPERCONVERGED,
    TLS_CUSTOM_POLICY,
    TLS_OLD_POLICY,
)


LOGGER = logging.getLogger(__name__)


@pytest.fixture()
def resources_dict():
    return {
        KubeVirt: {
            RESOURCE_NAME_STR: KUBEVIRT_HCO_NAME,
            RESOURCE_NAMESPACE_STR: py_config["hco_namespace"],
            KEY_NAME_STR: f"configuration{KEY_PATH_SEPARATOR}{TLS_SECURITY_PROFILE}",
        },
        SSP: {
            RESOURCE_NAME_STR: SSP_KUBEVIRT_HYPERCONVERGED,
            RESOURCE_NAMESPACE_STR: py_config["hco_namespace"],
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


@pytest.mark.polarion("CNV-9330")
def test_update_api_server(
    admin_client,
    hco_namespace,
    workers,
    workers_utility_pods,
    cnv_crypto_policy_matrix__function__,
    resources_dict,
    updated_api_server_crypto_policy,
    fips_enabled_cluster,
    services_to_check_connectivity,
):
    LOGGER.info(
        f"Validating crypto policy {cnv_crypto_policy_matrix__function__} settings on APIServer."
    )
    assert_crypto_policy_propagated_to_components(
        admin_client=admin_client,
        crypto_policy=cnv_crypto_policy_matrix__function__,
        resources_dict=resources_dict,
    )
    assert_no_crypto_policy_in_hco(
        admin_client=admin_client,
        crypto_policy=cnv_crypto_policy_matrix__function__,
        hco_namespace=hco_namespace.name,
        hco_name=py_config["hco_cr_name"],
    )

    # Old profile works only on non-FIPS cluster
    if (
        not fips_enabled_cluster
        or cnv_crypto_policy_matrix__function__ != TLS_OLD_POLICY
    ):
        assert_tls_version_connection(
            utility_pods=workers_utility_pods,
            node=workers[0],
            services=services_to_check_connectivity,
            minimal_version=MIN_TLS_VERSIONS[cnv_crypto_policy_matrix__function__],
        )

    # check ciphers only for Custom profile
    if cnv_crypto_policy_matrix__function__ == TLS_CUSTOM_POLICY:
        assert_tls_ciphers_blocked(
            utility_pods=workers_utility_pods,
            node=workers[0],
            services=services_to_check_connectivity,
            tls_version=MIN_TLS_VERSIONS[TLS_CUSTOM_POLICY],
            allowed_ciphers=TLS_CUSTOM_CIPHERS,
        )
