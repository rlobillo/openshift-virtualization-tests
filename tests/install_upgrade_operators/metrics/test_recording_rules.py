import pytest
from ocp_resources.resource import Resource

from utilities.constants import VIRT_API, VIRT_CONTROLLER, VIRT_HANDLER, VIRT_OPERATOR


pytestmark = [pytest.mark.post_upgrade, pytest.mark.sno]

virt_label_dict = {
    VIRT_API: f"{Resource.ApiGroup.KUBEVIRT_IO}={VIRT_API}",
    VIRT_HANDLER: f"{Resource.ApiGroup.KUBEVIRT_IO}={VIRT_HANDLER}",
    VIRT_OPERATOR: f"{Resource.ApiGroup.KUBEVIRT_IO}={VIRT_OPERATOR}",
    VIRT_CONTROLLER: f"{Resource.ApiGroup.KUBEVIRT_IO}={VIRT_CONTROLLER} ",
}


@pytest.mark.parametrize(
    "virt_pod_info_from_prometheus, virt_pod_names_by_label",
    [
        pytest.param(
            "kubevirt_virt_controller_ready",
            virt_label_dict[VIRT_CONTROLLER],
            marks=pytest.mark.polarion("CNV-7110"),
            id="kubevirt_virt_controller_ready",
        ),
        pytest.param(
            "kubevirt_virt_operator_ready",
            virt_label_dict[VIRT_OPERATOR],
            marks=pytest.mark.polarion("CNV-7111"),
            id="kubevirt_virt_operator_ready",
        ),
        pytest.param(
            "kubevirt_virt_operator_leading",
            virt_label_dict[VIRT_OPERATOR],
            marks=pytest.mark.polarion("CNV-7112"),
            id="kubevirt_virt_operator_leading",
        ),
        pytest.param(
            "kubevirt_virt_controller_leading",
            virt_label_dict[VIRT_CONTROLLER],
            marks=pytest.mark.polarion("CNV-7113"),
            id="kubevirt_virt_controller_leading",
        ),
    ],
    indirect=True,
)
def test_virt_recording_rules(
    prometheus,
    admin_client,
    hco_namespace,
    virt_pod_info_from_prometheus,
    virt_pod_names_by_label,
):
    """
    This test will check that recording rules for 'virt-operator and virt-controller'
    showing the pod information in the output.
    """
    # Check Pod names.
    assert (
        set(virt_pod_names_by_label) == virt_pod_info_from_prometheus
    ), f"Actual pods {virt_pod_names_by_label} not matching with expected pods {virt_pod_info_from_prometheus}"


@pytest.mark.parametrize(
    "virt_up_metrics_values, virt_pod_names_by_label",
    [
        pytest.param(
            "kubevirt_virt_api_up_total",
            virt_label_dict[VIRT_API],
            marks=pytest.mark.polarion("CNV-7106"),
            id="kubevirt_virt_api_up_total",
        ),
        pytest.param(
            "kubevirt_virt_operator_up_total",
            virt_label_dict[VIRT_OPERATOR],
            marks=pytest.mark.polarion("CNV-7107"),
            id="kubevirt_virt_operator_up_total",
        ),
        pytest.param(
            "kubevirt_virt_handler_up_total",
            virt_label_dict[VIRT_HANDLER],
            marks=pytest.mark.polarion("CNV-7108"),
            id="kubevirt_virt_handler_up_total",
        ),
        pytest.param(
            "kubevirt_virt_controller_up_total",
            virt_label_dict[VIRT_CONTROLLER],
            marks=pytest.mark.polarion("CNV-7109"),
            id="kubevirt_virt_controller_up_total",
        ),
    ],
    indirect=True,
)
def test_virt_up_recording_rules(
    prometheus,
    admin_client,
    hco_namespace,
    virt_up_metrics_values,
    virt_pod_names_by_label,
):
    """
    This test will check that 'up' recording rules for 'virt_api',
    'virt_controller','virt_operator', 'virt_handler' showing 'sum()' of pods in the output.
    More details on 'up': https://help.sumologic.com/Metrics/Kubernetes_Metrics#up-metrics

    Example:
        For 2 virt-api pods, 'kubevirt_virt_api_up_total' recording rule show 2 as output.
    """
    # Check values from Prometheus and acutal Pods.
    assert (
        len(virt_pod_names_by_label) == virt_up_metrics_values
    ), f"Actual pod count {virt_pod_names_by_label} not matching with expected pod count {virt_up_metrics_values}"
