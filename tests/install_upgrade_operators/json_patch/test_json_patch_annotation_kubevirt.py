import pytest
from ocp_resources.resource import Resource

from tests.install_upgrade_operators.json_patch.utils import (
    get_firing_alerts,
    get_metrics_value,
    is_tainted_config,
    wait_for_metrics_value_update,
)
from utilities.hco import update_hco_annotations, wait_for_hco_conditions


PATH = "migrations"
ALERT_NAME = "KubevirtHyperconvergedClusterOperatorUSModification"
COMPONENT = "kubevirt"
QUERY_STRING = "kubevirt_hco_unsafe_modification_count"


@pytest.fixture(scope="class")
def json_patched_kubevirt(
    admin_client, hco_namespace, hyperconverged_resource_scope_class
):
    with update_hco_annotations(
        resource=hyperconverged_resource_scope_class,
        path=PATH,
        value={"disableTLS": True},
        component=COMPONENT,
    ):
        yield
    assert not is_tainted_config(
        admin_client=admin_client, hco_namespace=hco_namespace.name
    )


@pytest.fixture(scope="class")
def kubevirt_alerts_before_test(prometheus):
    current_alerts = get_firing_alerts(prometheus=prometheus, alert_name=ALERT_NAME)
    assert (
        ALERT_NAME not in current_alerts.keys()
    ), f"Alert {ALERT_NAME} is currently in firing state: {current_alerts}"


@pytest.fixture(scope="class")
def kubevirt_unsafe_modification_metrics_before_test(prometheus):
    return get_metrics_value(
        prometheus=prometheus, component_name=COMPONENT, query_string=QUERY_STRING
    )


@pytest.mark.usefixtures(
    "kubevirt_unsafe_modification_metrics_before_test",
    "kubevirt_alerts_before_test",
    "json_patched_kubevirt",
)
class TestKubevirtJsonPatch:
    @pytest.mark.polarion("CNV-8689")
    def test_kubevirt_json_patch(
        self,
        admin_client,
        hco_namespace,
    ):
        wait_for_hco_conditions(
            admin_client=admin_client,
            hco_namespace=hco_namespace,
            expected_conditions={
                **{"TaintedConfiguration": Resource.Condition.Status.TRUE},
            },
        )

    @pytest.mark.polarion("CNV-9697")
    def test_kubevirt_json_patch_metrics(
        self, prometheus, kubevirt_unsafe_modification_metrics_before_test
    ):
        wait_for_metrics_value_update(
            prometheus=prometheus,
            component_name=COMPONENT,
            query_string=QUERY_STRING,
            previous_value=kubevirt_unsafe_modification_metrics_before_test,
        )

    @pytest.mark.polarion("CNV-9698")
    def test_kubevirt_json_patch_alert(self, prometheus):
        prometheus.alert_sampler(alert=ALERT_NAME)
