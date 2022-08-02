import pytest

from tests.network.checkup_framework.utils import (
    assert_checkup_timeout,
    assert_configmap_in_use,
    assert_successful_checkup,
)


pytestmark = pytest.mark.usefixtures("framework_resources")


@pytest.mark.parametrize(
    "latency_configmap",
    [
        pytest.param(
            pytest.lazy_fixture("latency_nonexistent_configmap"),
            marks=pytest.mark.polarion("CNV-8535"),
        ),
        pytest.param(
            pytest.lazy_fixture("latency_nonexistent_image_configmap"),
            marks=pytest.mark.polarion("CNV-8513"),
        ),
        pytest.param(
            pytest.lazy_fixture("latency_nonexistent_roles_configmap"),
            marks=pytest.mark.polarion("CNV-8512"),
        ),
        pytest.param(
            pytest.lazy_fixture("latency_timeout_configmap"),
            marks=pytest.mark.polarion("CNV-8656"),
        ),
    ],
)
def test_framework_failure(latency_configmap, latency_job):
    assert_checkup_timeout(configmap=latency_configmap, job=latency_job)


@pytest.mark.polarion("CNV-8453")
def test_concurrent_checkup_jobs(
    admin_client,
    default_latency_configmap,
    latency_job,
    latency_concurrent_job,
    framework_ns,
):
    # Make sure the second, concurrent, job failed due to the configMap being already in use:
    assert_configmap_in_use(
        admin_client=admin_client, job=latency_concurrent_job, framework_ns=framework_ns
    )


@pytest.mark.parametrize(
    "latency_configmap",
    [
        pytest.param(
            pytest.lazy_fixture("latency_no_roles_configmap"),
            marks=pytest.mark.polarion("CNV-8578"),
        ),
        pytest.param(
            pytest.lazy_fixture("latency_disconnected_configmap"),
            marks=pytest.mark.polarion("CNV-8511"),
        ),
    ],
)
def test_latency_checkup_failures(latency_configmap, latency_job):
    with pytest.raises(AssertionError):
        assert_successful_checkup(configmap=latency_configmap, job=latency_job)


@pytest.mark.parametrize(
    "latency_configmap",
    [
        pytest.param(
            pytest.lazy_fixture("latency_same_node_configmap"),
            marks=pytest.mark.polarion("CNV-8581"),
        ),
        pytest.param(
            pytest.lazy_fixture("latency_sriov_configmap"),
            marks=pytest.mark.polarion("CNV-8577"),
        ),
        pytest.param(
            pytest.lazy_fixture("default_latency_configmap"),
            marks=pytest.mark.polarion("CNV-8446"),
        ),
    ],
)
def test_latency_checkup(latency_configmap, latency_job):
    assert_successful_checkup(configmap=latency_configmap, job=latency_job)
