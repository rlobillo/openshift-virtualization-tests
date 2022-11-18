import logging

import pytest

from tests.install_upgrade_operators.crypto_policy.constants import (
    KEY_NAME_STR,
    RESOURCE_NAME_STR,
    RESOURCE_NAMESPACE_STR,
    RESOURCE_TYPE_STR,
)
from tests.install_upgrade_operators.crypto_policy.utils import (
    get_resource_crypto_policy,
)


LOGGER = logging.getLogger(__name__)


@pytest.fixture()
def resource_crypto_policy_settings(request, admin_client):
    yield get_resource_crypto_policy(
        admin_client=admin_client,
        resource=request.param.get(RESOURCE_TYPE_STR),
        name=request.param.get(RESOURCE_NAME_STR),
        namespace=request.param.get(RESOURCE_NAMESPACE_STR),
        key_name=request.param.get(KEY_NAME_STR),
    )
