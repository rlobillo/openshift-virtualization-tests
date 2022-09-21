import logging

import pytest

from tests.network.cnao_alerts.utils import wait_for_kubemacpool_pods_error_state
from utilities.constants import CLUSTER_NETWORK_ADDONS_OPERATOR, NON_EXISTS_IMAGE
from utilities.hco import ResourceEditorValidateHCOReconcile
from utilities.infra import wait_for_pods_running


LOGGER = logging.getLogger(__name__)


@pytest.fixture()
def updated_csv_dict_bad_kubemacpool_image(csv_scope_session):
    operator_image = "KUBEMACPOOL_IMAGE"
    csv_dict = csv_scope_session.instance.to_dict()
    for deployment in csv_dict["spec"]["install"]["spec"]["deployments"]:
        if deployment["name"] == CLUSTER_NETWORK_ADDONS_OPERATOR:
            container_env = deployment["spec"]["template"]["spec"]["containers"][0][
                "env"
            ]
            for env in container_env:
                if env["name"] == operator_image:
                    LOGGER.info(
                        f"Replacing {operator_image} {env['value']} with {NON_EXISTS_IMAGE}"
                    )
                    env["value"] = NON_EXISTS_IMAGE
                    return csv_dict

    raise ValueError(f"{CLUSTER_NETWORK_ADDONS_OPERATOR} not found")


@pytest.fixture()
def updated_cnao_kubemacpool_with_bad_image_csv(
    admin_client,
    hco_namespace,
    csv_scope_session,
    updated_csv_dict_bad_kubemacpool_image,
):
    with ResourceEditorValidateHCOReconcile(
        patches={csv_scope_session: updated_csv_dict_bad_kubemacpool_image}
    ):
        wait_for_kubemacpool_pods_error_state(
            dyn_client=admin_client, hco_namespace=hco_namespace
        )
        yield
    wait_for_pods_running(admin_client=admin_client, namespace=hco_namespace)
