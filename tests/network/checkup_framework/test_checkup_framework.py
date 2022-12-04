import pytest

from tests.network.checkup_framework.utils import assert_successful_checkup


pytestmark = pytest.mark.usefixtures("framework_resources")


@pytest.mark.parametrize(
    "network_type",
    [
        pytest.lazy_fixture("checkup_nad"),
        pytest.lazy_fixture("checkup_sriov_network"),
    ],
    indirect=True,
)
class TestCheckupLatency:
    @pytest.mark.polarion("CNV-9404")
    def test_basic_configmap(
        self, network_type, default_latency_configmap, latency_job
    ):
        assert_successful_checkup(configmap=default_latency_configmap, job=latency_job)
