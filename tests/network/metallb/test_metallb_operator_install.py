import pytest

from tests.network.metallb.utils import validate_metallb_pods_running


@pytest.mark.polarion("CNV-9574")
def test_metallb_operator(
    admin_client, created_metallb_namespace, installed_metallb_operator
):
    validate_metallb_pods_running(
        admin_client=admin_client,
        namespace=created_metallb_namespace,
    )
