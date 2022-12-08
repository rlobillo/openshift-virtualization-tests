import pytest

from tests.network.checkup_framework.utils import (
    assert_failure_reason_in_configmap,
    assert_identical_source_and_target_node,
    assert_successful_checkup,
    verify_failure_reason_in_log,
    wait_for_job_failure,
)


pytestmark = pytest.mark.usefixtures("framework_resources")


@pytest.mark.polarion("CNV-8578")
def test_disconnected_bridges_job_failures(latency_disconnected_configmap, latency_job):
    wait_for_job_failure(job=latency_job)
    assert_failure_reason_in_configmap(
        configmap=latency_disconnected_configmap,
        expected_failure_message="run: failed to run check: failed due to connectivity issue: \\d+ packets "
        "transmitted, 0 packets received",
    )


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
        self, unprivileged_client, network_type, default_latency_configmap, latency_job
    ):
        assert_successful_checkup(
            unprivileged_client=unprivileged_client,
            configmap=default_latency_configmap,
            job=latency_job,
        )

    @pytest.mark.polarion("CNV-8453")
    def test_concurrent_checkup_jobs(
        self,
        unprivileged_client,
        network_type,
        checkup_ns,
        default_latency_configmap,
        latency_job,
        latency_concurrent_job,
    ):
        # Make sure the second, concurrent, job failed due to the configMap being already in use:
        wait_for_job_failure(job=latency_concurrent_job)
        verify_failure_reason_in_log(
            unprivileged_client=unprivileged_client,
            job=latency_concurrent_job,
            checkup_ns=checkup_ns,
            failure_message="configMap is already in use",
        )

    @pytest.mark.polarion("CNV-8535")
    def test_nonexistent_configmap_job_failure(
        self,
        unprivileged_client,
        network_type,
        checkup_ns,
        default_latency_configmap,
        latency_nonexistent_configmap_env_job,
    ):
        env_variables = latency_nonexistent_configmap_env_job.instance.spec.template.spec.containers[
            0
        ].env
        configmap_name = [
            variable["value"]
            for variable in env_variables
            if variable["name"] == "CONFIGMAP_NAME"
        ][0]
        wait_for_job_failure(job=latency_nonexistent_configmap_env_job)
        verify_failure_reason_in_log(
            unprivileged_client=unprivileged_client,
            job=latency_nonexistent_configmap_env_job,
            checkup_ns=checkup_ns,
            failure_message=f'configmaps "{configmap_name}" not found',
        )

    @pytest.mark.polarion("CNV-8581")
    def test_same_node_configmap(
        self,
        unprivileged_client,
        network_type,
        checkup_ns,
        latency_same_node_configmap,
        latency_job,
    ):
        assert_successful_checkup(
            unprivileged_client=unprivileged_client,
            configmap=latency_same_node_configmap,
            job=latency_job,
        )
        assert_identical_source_and_target_node(configmap=latency_same_node_configmap)
