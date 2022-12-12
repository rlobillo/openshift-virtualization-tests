"""
Firing alerts for kubevirt pods
"""

import pytest

from tests.compute.utils import verify_no_listed_alerts_on_cluster
from utilities.hco import ResourceEditorValidateHCOReconcile


VIRT_ALERTS_LIST = [
    "VirtOperatorDown",
    "NoReadyVirtOperator",
    "LowVirtOperatorCount",
    "VirtAPIDown",
    "LowVirtOperatorCount",
    "VirtHandlerDaemonSetRolloutFailing",
    "LowReadyVirtOperatorsCount",
    "NoLeadingVirtOperator",
    "VirtOperatorRESTErrorsBurst",
    "VirtOperatorRESTErrorsHigh",
    "VirtApiRESTErrorsBurst",
    "VirtApiRESTErrorsHigh",
    "LowReadyVirtControllersCount",
    "NoReadyVirtController",
    "VirtControllerRESTErrorsHigh",
    "VirtControllerRESTErrorsBurst",
    "VirtHandlerRESTErrorsHigh",
    "VirtHandlerRESTErrorsBurst",
    "KubeVirtComponentExceedsRequestedMemory",
    "KubeVirtComponentExceedsRequestedCPU",
]


@pytest.fixture()
def virt_handler_daemonset_with_bad_image(virt_handler_daemonset_scope_module):
    with ResourceEditorValidateHCOReconcile(
        patches={
            virt_handler_daemonset_scope_module: {
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {"name": "virt-handler", "image": "bad_image"}
                            ]
                        }
                    }
                }
            }
        }
    ):
        yield


class TestVirtAlerts:
    @pytest.mark.polarion("CNV-7610")
    def test_no_virt_alerts_on_healthy_cluster(
        self,
        prometheus,
    ):
        verify_no_listed_alerts_on_cluster(
            prometheus=prometheus, alerts_list=VIRT_ALERTS_LIST
        )

    @pytest.mark.order(after="test_no_virt_alerts_on_healthy_cluster")
    @pytest.mark.parametrize(
        "scaled_deployment, alert",
        [
            pytest.param(
                {"deployment_name": "virt-api", "replicas": 0},
                "VirtAPIDown",
                marks=pytest.mark.polarion("CNV-3603"),
            ),
            pytest.param(
                {"deployment_name": "virt-controller", "replicas": 0},
                "VirtControllerDown",
                marks=pytest.mark.polarion("CNV-3604"),
            ),
            pytest.param(
                {"deployment_name": "virt-operator", "replicas": 0},
                "VirtOperatorDown",
                marks=pytest.mark.polarion("CNV-7482"),
            ),
        ],
        indirect=["scaled_deployment"],
    )
    def test_alert_virt_pods_down(
        self,
        prometheus,
        disabled_virt_operator,
        scaled_deployment,
        alert,
    ):
        prometheus.alert_sampler(alert=alert)

    @pytest.mark.order(after="test_no_virt_alerts_on_healthy_cluster")
    @pytest.mark.parametrize(
        "scaled_deployment, alert",
        [
            pytest.param(
                {"deployment_name": "virt-api", "replicas": 1},
                "LowVirtAPICount",
                marks=pytest.mark.polarion("CNV-7601"),
            ),
            pytest.param(
                {"deployment_name": "virt-controller", "replicas": 1},
                "LowVirtControllersCount",
                marks=pytest.mark.polarion("CNV-7600"),
            ),
            pytest.param(
                # replicas for virt-operator should be 0, otherwise it will restore all pods
                {"deployment_name": "virt-operator", "replicas": 0},
                "LowVirtOperatorCount",
                marks=pytest.mark.polarion("CNV-7599"),
            ),
        ],
        indirect=["scaled_deployment"],
    )
    def test_alert_virt_pods_low_count(
        self,
        prometheus,
        skip_when_one_node,
        disabled_virt_operator,
        scaled_deployment,
        alert,
    ):
        prometheus.alert_sampler(alert=alert)

    @pytest.mark.order(after="test_no_virt_alerts_on_healthy_cluster")
    @pytest.mark.polarion("CNV-3814")
    def test_alert_virt_handler(
        self,
        prometheus,
        disabled_virt_operator,
        virt_handler_daemonset_with_bad_image,
    ):
        prometheus.alert_sampler(alert="VirtHandlerDaemonSetRolloutFailing")
