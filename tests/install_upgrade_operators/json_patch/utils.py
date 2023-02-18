import logging

from ocp_resources.resource import Resource
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler

from utilities.constants import TIMEOUT_5MIN, TIMEOUT_30SEC
from utilities.hco import HCO_JSONPATCH_ANNOTATION_COMPONENT_DICT


LOGGER = logging.getLogger(__name__)


def get_annotation_name_for_component(component_name):
    return (
        f"{HCO_JSONPATCH_ANNOTATION_COMPONENT_DICT[component_name]['api_group_prefix']}."
        f"{Resource.ApiGroup.KUBEVIRT_IO}/jsonpatch"
    )


def get_firing_alerts(prometheus, alert_name):
    firing_alerts = []
    all_alerts = prometheus.alerts["data"].get("alerts")
    for alert in all_alerts:
        if alert_name == alert["labels"]["alertname"] and alert["state"] == "firing":
            firing_alerts.append(alert)
    return firing_alerts


def wait_for_alert(prometheus, alert_name, component_name):
    annotation_name = get_annotation_name_for_component(component_name=component_name)
    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_5MIN,
        sleep=TIMEOUT_30SEC,
        func=get_firing_alerts,
        prometheus=prometheus,
        alert_name=alert_name,
    )
    sample = None
    try:
        for sample in samples:
            if sample and sample[0]["labels"]["annotation_name"] == annotation_name:
                LOGGER.info(f"Found alert: {sample} in firing state.")
                return
    except TimeoutExpiredError:
        LOGGER.error(
            f"Alert: {alert_name} did not get created for {annotation_name} in {TIMEOUT_5MIN} seconds."
            f"Current firing alerts are:\n {sample}"
        )


def wait_for_firing_alert_clean_up(prometheus, alert_name):
    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_5MIN,
        sleep=TIMEOUT_30SEC,
        func=get_firing_alerts,
        prometheus=prometheus,
        alert_name=alert_name,
    )
    try:
        for sample in samples:
            if not sample:
                return
    except TimeoutExpiredError:
        LOGGER.error(
            f"Alert: {alert_name} did not get clear in {TIMEOUT_5MIN} seconds."
        )


def get_metrics_value(prometheus, query_string, component_name):
    annotation_name = get_annotation_name_for_component(component_name=component_name)
    query = f"{query_string}" '{annotation_name="' f'{annotation_name}"' "}"
    metric_results = prometheus.query(query=query)["data"]["result"]
    return int(metric_results[0]["value"][1]) if metric_results else 0


def filter_metric_by_component(metrics, metric_name, component_name):
    annotation_name = get_annotation_name_for_component(component_name=component_name)
    for metric in metrics:
        if (
            metric["metric"]["annotation_name"] == annotation_name
            and metric["metric"]["__name__"] == metric_name
        ):
            return int(metric["value"][1])


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
