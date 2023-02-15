import logging

from ocp_resources.resource import Resource
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler

from utilities.constants import TIMEOUT_5MIN, TIMEOUT_30SEC
from utilities.hco import HCO_JSONPATCH_ANNOTATION_COMPONENT_DICT
from utilities.infra import get_hyperconverged_resource


LOGGER = logging.getLogger(__name__)


def get_firing_alerts(prometheus, alert_name):
    fired_alerts = {}
    alert_state = prometheus.get_alert(alert=alert_name)
    if alert_state and alert_state[0]["metric"]["alertstate"] == "firing":
        fired_alerts[alert_name] = alert_state
    LOGGER.info(f"Alert query: {alert_name}, current firing alerts: {fired_alerts}")
    return fired_alerts


def get_metrics_value(prometheus, component_name, query_string):
    annotation_name = (
        f"{HCO_JSONPATCH_ANNOTATION_COMPONENT_DICT[component_name]['api_group_prefix']}."
        f"{Resource.ApiGroup.KUBEVIRT_IO}/jsonpatch"
    )
    query = f"{query_string}" '{annotation_name="' f'{annotation_name}"' "}"
    metric_results = prometheus.query(query=query)["data"]["result"]
    return int(metric_results[0]["value"][1]) if metric_results else 0


def wait_for_metrics_value_update(
    prometheus, component_name, query_string, previous_value
):
    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_5MIN,
        sleep=TIMEOUT_30SEC,
        func=get_metrics_value,
        prometheus=prometheus,
        component_name=component_name,
        query_string=query_string,
    )
    try:
        for sample in samples:
            if sample == previous_value + 1:
                return sample
    except TimeoutExpiredError:
        LOGGER.error(
            f"Query string: {query_string} for component: {component_name}, previous value: {previous_value}."
        )
        raise


def is_tainted_config(admin_client, hco_namespace):
    hco = get_hyperconverged_resource(client=admin_client, hco_ns_name=hco_namespace)
    return (
        True
        if [
            condition
            for condition in hco.instance.status.conditions
            if condition["type"] == "TaintedConfiguration"
        ]
        else False
    )
