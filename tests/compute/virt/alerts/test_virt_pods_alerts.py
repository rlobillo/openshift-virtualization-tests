"""
Firing alerts for kubevirt pods
"""

import pytest

from utilities.hco import ResourceEditorValidateHCOReconcile


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
    @pytest.mark.order(after="test_no_virt_alerts_on_healthy_cluster")
    @pytest.mark.polarion("CNV-3814")
    def test_alert_virt_handler(
        self,
        prometheus,
        disabled_virt_operator,
        virt_handler_daemonset_with_bad_image,
    ):
        prometheus.alert_sampler(alert="VirtHandlerDaemonSetRolloutFailing")
