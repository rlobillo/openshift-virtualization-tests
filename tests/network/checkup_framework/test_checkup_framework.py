import pytest

from tests.network.checkup_framework.constants import NONEXISTING_CONFIGMAP
from tests.network.checkup_framework.utils import (
    assert_failure_reason_in_configmap,
    assert_source_and_target_nodes,
    verify_failure_reason_in_log,
)


pytestmark = pytest.mark.usefixtures("framework_resources")
CONNECTIVITY_ISSUE_ERROR = (
    "run: failed to run check: failed due to connectivity issue: \\d+ packets "
    "transmitted, 0 packets received"
)


@pytest.mark.parametrize(
    "latency_configmap",
    [
        pytest.param(
            pytest.lazy_fixture("latency_disconnected_configmap"),
            marks=pytest.mark.polarion("CNV-8578"),
        ),
        pytest.param(
            pytest.lazy_fixture("latency_disconnected_configmap_sriov"),
            marks=pytest.mark.polarion("CNV-9535"),
        ),
    ],
)
def test_disconnected_network_job_failure(
    latency_configmap, latency_job, latency_job_failure
):
    assert_failure_reason_in_configmap(
        configmap=latency_configmap,
        expected_failure_message=CONNECTIVITY_ISSUE_ERROR,
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
    @pytest.mark.parametrize(
        "latency_configmap, expected_nodes_identical",
        [
            pytest.param(
                pytest.lazy_fixture("default_latency_configmap"),
                False,
                marks=pytest.mark.polarion("CNV-9404"),
            ),
            pytest.param(
                pytest.lazy_fixture("latency_same_node_configmap"),
                True,
                marks=pytest.mark.polarion("CNV-8581"),
            ),
        ],
    )
    def test_basic_configmap(
        self,
        checkup_ns,
        network_type,
        latency_configmap,
        latency_job,
        expected_nodes_identical,
        latency_job_success,
    ):
        assert_source_and_target_nodes(
            configmap=latency_configmap,
            expected_nodes_identical=expected_nodes_identical,
        )

    @pytest.mark.parametrize(
        "latency_configmap",
        [
            pytest.param(
                pytest.lazy_fixture("default_latency_configmap"),
                marks=pytest.mark.polarion("CNV-8453"),
            ),
        ],
    )
    def test_concurrent_checkup_jobs(
        self,
        unprivileged_client,
        checkup_ns,
        network_type,
        latency_configmap,
        latency_job,
        latency_concurrent_job,
        latency_concurrent_job_failure,
    ):
        # Make sure the second, concurrent, job failed due to the configMap being already in use:
        verify_failure_reason_in_log(
            unprivileged_client=unprivileged_client,
            job=latency_concurrent_job,
            checkup_ns=checkup_ns,
            failure_message="configMap is already in use",
        )

    @pytest.mark.parametrize(
        "latency_job, failure_message",
        [
            pytest.param(
                pytest.lazy_fixture("latency_nonexistent_configmap_env_job"),
                f'configmaps "{NONEXISTING_CONFIGMAP}" not found',
                marks=pytest.mark.polarion("CNV-8535"),
            ),
            pytest.param(
                pytest.lazy_fixture("latency_no_env_variables_job"),
                'missing required environment variable: "CONFIGMAP_NAMESPACE"',
                marks=pytest.mark.polarion("CNV-9482"),
            ),
        ],
    )
    def test_job_failure(
        self,
        unprivileged_client,
        checkup_ns,
        network_type,
        default_latency_configmap,
        latency_job,
        failure_message,
        latency_job_failure,
    ):
        verify_failure_reason_in_log(
            unprivileged_client=unprivileged_client,
            job=latency_job,
            checkup_ns=checkup_ns,
            failure_message=failure_message,
        )

    @pytest.mark.parametrize(
        "latency_configmap, failure_message",
        [
            pytest.param(
                pytest.lazy_fixture("latency_nonexistent_nad_configmap"),
                'setup: network-attachment-definitions.k8s.cni.cncf.io "non-existing-nad" not found',
                marks=pytest.mark.polarion("CNV-9479"),
            ),
            pytest.param(
                pytest.lazy_fixture("latency_nonexistent_namespace_configmap"),
                'test-checkup-framework-sa" cannot get resource '
                '"network-attachment-definitions" in API group "k8s.cni.cncf.io" in the namespace '
                '"non-existing-namespace"',
                marks=pytest.mark.polarion("CNV-9481"),
            ),
            pytest.param(
                pytest.lazy_fixture("latency_nonexistent_node_configmap"),
                "setup: failed to wait for VMI 'test-checkup-framework/latency-check-source' IP address "
                "to appear on status: timed out waiting for the condition",
                marks=pytest.mark.polarion("CNV-9476"),
            ),
        ],
    )
    def test_configmap_error_job_failure(
        self,
        unprivileged_client,
        checkup_ns,
        network_type,
        latency_configmap,
        latency_job,
        failure_message,
        latency_job_failure,
    ):
        verify_failure_reason_in_log(
            unprivileged_client=unprivileged_client,
            job=latency_job,
            checkup_ns=checkup_ns,
            failure_message=failure_message,
        )
