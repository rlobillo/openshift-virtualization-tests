import pytest

from tests.install_upgrade_operators.json_patch.constants import (
    ALERT_NAME,
    QUERY_STRING,
)
from tests.install_upgrade_operators.json_patch.utils import get_firing_alerts


@pytest.fixture(scope="class")
def kubevirt_alerts_before_test(prometheus):
    return get_firing_alerts(prometheus=prometheus, alert_name=ALERT_NAME)


@pytest.fixture(scope="class")
def kubevirt_all_unsafe_modification_metrics_before_test(prometheus):
    return prometheus.query_sampler(query=QUERY_STRING)
