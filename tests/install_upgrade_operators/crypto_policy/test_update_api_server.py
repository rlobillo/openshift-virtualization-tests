import logging

import pytest
from ocp_resources.cdi import CDI
from ocp_resources.hyperconverged import HyperConverged
from ocp_resources.kubevirt import KubeVirt
from ocp_resources.network_addons_config import NetworkAddonsConfig
from ocp_resources.ssp import SSP
from pytest_testconfig import config as py_config

from tests.install_upgrade_operators.constants import KEY_PATH_SEPARATOR
from tests.install_upgrade_operators.crypto_policy.constants import (
    CRYPTO_POLICY_EXPECTED_DICT,
    KEY_NAME_STR,
    MANAGED_CRS_LIST,
    RESOURCE_NAME_STR,
    RESOURCE_NAMESPACE_STR,
    TLS_SECURITY_PROFILE,
)
from tests.install_upgrade_operators.crypto_policy.utils import (
    get_resource_crypto_policy,
    wait_for_crypto_policy_update,
)
from utilities.constants import (
    CDI_KUBEVIRT_HYPERCONVERGED,
    CLUSTER_RESOURCE_NAME,
    KUBEVIRT_HCO_NAME,
    SSP_KUBEVIRT_HYPERCONVERGED,
)
from utilities.infra import is_bug_open


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
    cnv_crypto_policy_matrix__function__,
    resources_dict,
    updated_api_server_crypto_policy,
):
    LOGGER.info(
        f"Validating crypto policy {cnv_crypto_policy_matrix__function__} settings on APIServer."
    )
    error_messages = []
    for resource in MANAGED_CRS_LIST:
        expected_value = CRYPTO_POLICY_EXPECTED_DICT[
            cnv_crypto_policy_matrix__function__
        ][resource]
        error_message = wait_for_crypto_policy_update(
            admin_client=admin_client,
            resource=resource,
            resource_namespace=resources_dict[resource].get(RESOURCE_NAMESPACE_STR),
            resource_name=resources_dict[resource][RESOURCE_NAME_STR],
            key_name=resources_dict[resource][KEY_NAME_STR],
            expected_policy=expected_value,
        )
        if error_message:
            if resource == KubeVirt and is_bug_open(bug_id="2139235"):
                continue
            error_messages.append(error_message)
    assert not error_messages, (
        f"Updating APIServer {CLUSTER_RESOURCE_NAME} with {cnv_crypto_policy_matrix__function__}, failed for the "
        f"following CRs: {''.join(error_messages)}"
    )
    hco_crypto_policy = get_resource_crypto_policy(
        admin_client=admin_client,
        resource=HyperConverged,
        name=py_config["hco_cr_name"],
        namespace=py_config["hco_namespace"],
        key_name=TLS_SECURITY_PROFILE,
    )
    assert not hco_crypto_policy, (
        f"On updating APIServer {CLUSTER_RESOURCE_NAME} with {cnv_crypto_policy_matrix__function__}, HCO crypto policy "
        f"was set up to {hco_crypto_policy}:"
    )
