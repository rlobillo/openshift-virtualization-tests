import json
import logging
from multiprocessing import Process

from ocp_resources.cluster_operator import ClusterOperator
from ocp_resources.cluster_version import ClusterVersion
from ocp_resources.pod import Pod
from ocp_resources.resource import Resource
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from ocp_utilities.utils import run_command
from ocp_wrapper_data_collector.data_collector import (
    collect_resources_yaml_instance,
    write_to_file,
)
from openshift.dynamic.exceptions import NotFoundError, ResourceNotFoundError

from tests.install_upgrade_operators.utils import (
    wait_for_install_plan,
    wait_for_operator_condition,
)
from utilities.constants import (
    BASE_EXCEPTIONS_DICT,
    HCO_OPERATOR,
    IMAGE_CRON_STR,
    OPERATOR_NAME_SUFFIX,
    TIMEOUT_10MIN,
    TIMEOUT_20MIN,
    TIMEOUT_30MIN,
    TIMEOUT_180MIN,
    TSC_FREQUENCY,
)
from utilities.data_collector import get_data_collector_dict
from utilities.hco import wait_for_hco_conditions, wait_for_hco_version
from utilities.infra import (
    cluster_resource,
    cnv_target_images,
    get_clusterversion,
    get_deployments,
    get_pod_by_name_prefix,
    wait_for_consistent_resource_conditions,
)
from utilities.operator import approve_install_plan, wait_for_mcp_update_completion


LOGGER = logging.getLogger(__name__)
TIER_2_PODS_TYPE = "tier-2"
FIRING_STATE = "firing"


def wait_for_new_operator_pod(
    dyn_client,
    hco_namespace,
    operator_name,
    operator_target_info,
    upgrade_resilience=False,
):
    """
    Wait for a new operator pod to be created and running


    Args:
        dyn_client (DynamicClient): OCP Client to use
        hco_namespace (Namespace): HCO namespace
        operator_name (str): Operator name as extracted from its deployment
        operator_target_info (dict): With "image" and "strategy" as extracted from its deployment
        upgrade_resilience (bool, default: False): if True, new operator pods will be deleted during the upgrade

    Raises:
        TimeoutExpiredError: if a pod with the expected image is not created or if the pod is not running.
    """

    def _is_expected_operator_pod_image(
        _dyn_client, _operator_name, _hco_namespace, _operator_target_info
    ):
        operator_pods = get_pod_by_name_prefix(
            dyn_client=_dyn_client,
            pod_prefix=_operator_name,
            namespace=_hco_namespace,
            get_all=True,
        )
        return [
            _pod
            for _pod in operator_pods
            if _pod.instance.spec.containers[0].image == _operator_target_info["image"]
        ]

    LOGGER.info(
        f"Verify new operator pod {operator_name} replacement. Running upgrade resiliency: {upgrade_resilience}"
    )

    new_pod_sampler = TimeoutSampler(
        wait_timeout=TIMEOUT_30MIN,
        sleep=1,
        func=_is_expected_operator_pod_image,
        _dyn_client=dyn_client,
        _operator_name=operator_name,
        _hco_namespace=hco_namespace,
        _operator_target_info=operator_target_info,
    )

    new_operator_pod = None
    operator_resiliency = upgrade_resilience
    try:
        for pod in new_pod_sampler:
            if pod:
                new_operator_pod = pod[0]
                if operator_resiliency:
                    new_operator_pod.delete(wait=True, timeout=TIMEOUT_10MIN)
                    operator_resiliency = False
                    continue
                break
    except TimeoutExpiredError:
        LOGGER.error(
            f"Operator {operator_name} new pods are not created, expected: {operator_target_info}"
        )
        raise

    status_running = new_operator_pod.Status.RUNNING
    LOGGER.info(f"Wait for {new_operator_pod.name} to be {status_running}")
    new_operator_pod.wait_for_status(status=status_running, timeout=TIMEOUT_30MIN)


def wait_for_operator_pods_replacement(
    dyn_client,
    hco_namespace,
    operators_target_versions,
    upgrade_resilience,
):
    LOGGER.info("Wait for operators replacement.")

    processes = []

    for operator_name, operator_target_info in operators_target_versions.items():
        sub_process = Process(
            name=operator_name,
            target=wait_for_new_operator_pod,
            kwargs={
                "dyn_client": dyn_client,
                "hco_namespace": hco_namespace,
                "operator_name": operator_name,
                "operator_target_info": operator_target_info,
                "upgrade_resilience": upgrade_resilience,
            },
        )
        processes.append(sub_process)
        sub_process.start()

    for process in processes:
        process.join()

    failed_processes = {
        process.name: process.exitcode for process in processes if process.exitcode != 0
    }
    assert (
        not failed_processes
    ), f"Failures during operator pods replacement. Failed processes={failed_processes}"


def get_cluster_pods(dyn_client, hco_namespace, pods_type):
    """
    Returns a list of cluster pods:
    pods_type - operator/tier-2 (non-operator) /all
    """
    # pods_type is "all"
    cluster_pods = list(
        cluster_resource(Pod).get(dyn_client=dyn_client, namespace=hco_namespace)
    )
    # Operator pods
    if pods_type == OPERATOR_NAME_SUFFIX:
        cluster_pods = [pod for pod in cluster_pods if OPERATOR_NAME_SUFFIX in pod.name]
    # Tier-2 pods (created by operators)
    elif pods_type == TIER_2_PODS_TYPE:
        cluster_pods = [
            pod for pod in cluster_pods if OPERATOR_NAME_SUFFIX not in pod.name
        ]

    assert cluster_pods, f"No cluster pods of type {pods_type} were found."
    return cluster_pods


def get_operator_by_name(dyn_client, hco_namespace, operator_name):
    pods = list(
        cluster_resource(Pod).get(dyn_client=dyn_client, namespace=hco_namespace)
    )
    operator_pod = list(filter(lambda x: operator_name in x.name, pods))[0]
    return operator_pod


def assert_only_expected_pods_exist(
    dyn_client,
    hco_namespace,
    expected_images,
    pods_type,
):
    """
    Verifies that only pods with expected images (taken from target CSV) exist.

    Args:
        dyn_client (DynamicClient): OCP Client to use
        hco_namespace (Namespace): HCO namespace
        expected_images (list): of expected images
        pods_type (str): operator or tier-2

    Raises:
        AssertionError if there are pods' images which do not match the expected images list
    """
    LOGGER.info(
        f"Verify {pods_type} pods have the right image and no leftover pods exist"
    )
    current_cnv_pods = get_cluster_pods(
        dyn_client=dyn_client, hco_namespace=hco_namespace, pods_type=pods_type
    )
    expected_images = cnv_target_images(
        target_related_images_name_and_versions=expected_images
    )
    mismatching_pods = {
        pod.name: pod.instance.spec.containers[0].image
        for pod in current_cnv_pods
        if pod.instance.spec.containers[0].image not in expected_images
        and not (
            IMAGE_CRON_STR in pod.name
            or pod.instance.status.phase in pod.Status.SUCCEEDED
        )
    }

    assert not mismatching_pods, (
        f"The following {pods_type} pods images were not replaced / removed: {mismatching_pods}."
        f"Expected images: {expected_images}"
    )


def get_nodes_taints(nodes):
    """
    Capture taints information out of all nodes and create a dictionary.

    Args:
        nodes (list): list of Node objects

    Returns:
        nodes_dict (dict): dictionary containing taints information associated with every nodes
    """
    return {node.name: node.instance.spec.taints for node in nodes}


def verify_nodes_taints_after_upgrade(nodes, nodes_taints_before_upgrade):
    """
    Verify that none of the nodes taints changed after cnv upgrade

    Args:
        nodes (list): list of Node objects
        nodes_taints_before_upgrade(dict): dictionary containing node taints
    """
    nodes_taints_after_upgrade = get_nodes_taints(nodes=nodes)
    taint_diff = {
        node_name: {
            "before": nodes_taints_before_upgrade[node_name],
            "after": nodes_taints_after_upgrade[node_name],
        }
        for node_name in nodes_taints_after_upgrade
        if nodes_taints_after_upgrade[node_name]
        != nodes_taints_before_upgrade[node_name]
    }
    assert not taint_diff, f"Mismatch in node taints found after upgrade: {taint_diff}"


def get_nodes_labels(nodes, cnv_upgrade):
    """
    Based on cnv_upgrade type being used, this function captures appropriate labels information from the nodes.
    For ocp upgrade, any labels containing Resource.ApiGroup.KUBEVIRT_IO string would be collected to ensure such
    labels remains unaltered post ocp upgrade, while for cnv upgrade non-cnv labels would be checked to ensure no
    accidental modification happened to those during upgrade.
    Please note: node.labels are tuples

    Args:
        nodes (list): list of Node objects
        cnv_upgrade (bool): True if cnv upgrade else False

    Returns:
        nodes_dict (dict): dictionary containing labels and taints information associated with every nodes
    """
    return {
        node.name: {
            label_key: label_value
            for label_key, label_value in node.labels
            if (cnv_upgrade and Resource.ApiGroup.KUBEVIRT_IO not in label_key)
            or (
                not cnv_upgrade
                and Resource.ApiGroup.KUBEVIRT_IO in label_key
                and TSC_FREQUENCY not in label_key
            )
        }
        for node in nodes
    }


def verify_nodes_labels_after_upgrade(nodes, nodes_labels_before_upgrade, cnv_upgrade):
    """
    Validate that node labels after upgrade are as expected, in case of y stream upgrade ensures that expected changes
    in node labels don't cause failure

    Args:
        nodes (list): List of node objects
        nodes_labels_before_upgrade (dict): dictionary containing labels of all nodes in the cluster
        cnv_upgrade (boolean): indicates if a given upgrade is ocp or cnv upgrade

    Raises:
        AssertionError: Asserts on node label mismatch
    """
    nodes_labels_after_upgrade = get_nodes_labels(nodes=nodes, cnv_upgrade=cnv_upgrade)
    label_diff = get_dict_diff(
        before_upgrade=nodes_labels_before_upgrade,
        after_upgrade=nodes_labels_after_upgrade,
    )
    assert not label_diff, f"Mismatch in node labels after upgrade: {label_diff}"


def get_dict_diff(before_upgrade, after_upgrade):
    """
    Compare before and after upgrade values and create a dict with difference, incase of change in values post upgrade

    Args:
        before_upgrade(dict): before upgrade values
        after_upgrade(dict): after upgrade value

    Returns:
        dict: dictionary indicating difference
    """
    return {
        node_name: {
            "before": before_upgrade[node_name],
            "after": after_upgrade[node_name],
        }
        for node_name in after_upgrade
        if after_upgrade[node_name] != before_upgrade[node_name]
    }


def verify_cnv_pods_are_running(dyn_client, hco_namespace):
    def _get_pods_that_are_not_running():
        return [
            pod.name
            for pod in get_cluster_pods(
                dyn_client=dyn_client, hco_namespace=hco_namespace.name, pods_type="all"
            )
            if pod.status
            not in (Pod.Status.RUNNING, Pod.Status.COMPLETED, Pod.Status.SUCCEEDED)
        ]

    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_10MIN,
        sleep=10,
        func=_get_pods_that_are_not_running,
    )
    sample = None
    try:
        for sample in samples:
            if not sample:
                return
    except TimeoutExpiredError:
        LOGGER.error(f"Some pods are not running: {sample}.")
        raise


def update_icsp_stage_mirror(icsp_file_path):
    # TODO: Remove once mirror catalog from stage is fixed
    rc, out, err = run_command(
        command=[
            "sed",
            "-i",
            "-e",
            "s|/container-native-virtualization-\\(.*\\)|/\\1|g",
            icsp_file_path,
        ]
    )
    assert (
        rc
    ), f"Failed to update stage mirror in ICSP: icsp_file_path={icsp_file_path} out={out} err={err}"


def verify_cnv_post_upgrade_conditions(
    dyn_client,
    hco_namespace,
    cnv_target_version,
    target_operator_pods_images,
    target_tier_2_images_name_and_versions,
):

    LOGGER.info("Validate post upgrade HCO status:")
    wait_for_hco_post_upgrade_state(
        dyn_client=dyn_client,
        hco_namespace=hco_namespace,
        cnv_target_version=cnv_target_version,
    )
    wait_for_post_upgrade_deployments_replicas(
        dyn_client=dyn_client, hco_namespace=hco_namespace
    )

    assert_only_expected_pods_exist(
        dyn_client=dyn_client,
        hco_namespace=hco_namespace.name,
        expected_images=target_operator_pods_images,
        pods_type=OPERATOR_NAME_SUFFIX,
    )

    assert_only_expected_pods_exist(
        dyn_client=dyn_client,
        hco_namespace=hco_namespace.name,
        expected_images=target_tier_2_images_name_and_versions,
        pods_type=TIER_2_PODS_TYPE,
    )


def wait_for_hco_post_upgrade_state(dyn_client, hco_namespace, cnv_target_version):
    LOGGER.info("Wait for HCO operator pod to be ready")
    hco_operator_pod = get_pod_by_name_prefix(
        dyn_client=dyn_client, pod_prefix=HCO_OPERATOR, namespace=hco_namespace.name
    )
    hco_operator_pod.wait_for_condition(
        condition=Pod.Condition.READY,
        status=Pod.Condition.Status.TRUE,
        timeout=TIMEOUT_10MIN,
    )

    LOGGER.info(f"Wait for HCO version to be updated to {cnv_target_version}.")
    wait_for_hco_version(
        client=dyn_client,
        hco_ns_name=hco_namespace.name,
        cnv_version=cnv_target_version,
    )
    LOGGER.info("Wait for HCO stable conditions after upgrade")
    wait_for_hco_conditions(
        admin_client=dyn_client,
        hco_namespace=hco_namespace,
        wait_timeout=TIMEOUT_20MIN,
    )


def wait_for_post_upgrade_deployments_replicas(dyn_client, hco_namespace):
    LOGGER.info("Wait for deployments replicas.")
    for deployment in get_deployments(
        admin_client=dyn_client, namespace=hco_namespace.name
    ):
        deployment.wait_for_replicas(timeout=TIMEOUT_10MIN)


def verify_upgrade_cnv(
    dyn_client,
    hco_namespace,
    upgrade_resilience,
    cnv_target_version,
    hco_target_version,
    target_csv,
    target_operator_pods_images_name_and_strategy,
    target_tier_2_images_name_and_versions,
):
    wait_for_operator_pods_replacement(
        dyn_client=dyn_client,
        hco_namespace=hco_namespace.name,
        operators_target_versions=target_operator_pods_images_name_and_strategy,
        upgrade_resilience=upgrade_resilience,
    )
    LOGGER.info(f"Wait for csv: {target_csv.name} to be in SUCCEEDED state.")
    target_csv.wait_for_status(
        status=target_csv.Status.SUCCEEDED,
        timeout=TIMEOUT_10MIN,
        stop_status=None,
    )
    LOGGER.info(
        f"Wait for operator condition {hco_target_version} to reach upgradable: True"
    )
    wait_for_operator_condition(
        dyn_client=dyn_client,
        hco_namespace=hco_namespace.name,
        name=hco_target_version,
        upgradable=True,
    )
    verify_cnv_post_upgrade_conditions(
        dyn_client=dyn_client,
        hco_namespace=hco_namespace,
        cnv_target_version=cnv_target_version,
        target_operator_pods_images=target_operator_pods_images_name_and_strategy,
        target_tier_2_images_name_and_versions=target_tier_2_images_name_and_versions,
    )


def approve_cnv_upgrade_install_plan(dyn_client, hco_namespace, hco_target_version):
    LOGGER.info("Get the upgrade install plan.")
    install_plan = wait_for_install_plan(
        dyn_client=dyn_client,
        hco_namespace=hco_namespace,
        hco_target_version=hco_target_version,
    )

    LOGGER.info(
        f"Approve the upgrade install plan {install_plan.name} to trigger the upgrade."
    )
    approve_install_plan(install_plan=install_plan)


def wait_for_cluster_version_stable_conditions(admin_client):
    wait_for_consistent_resource_conditions(
        dynamic_client=admin_client,
        expected_conditions={
            Resource.Condition.AVAILABLE: Resource.Condition.Status.TRUE,
            Resource.Condition.PROGRESSING: Resource.Condition.Status.FALSE,
            Resource.Condition.FAILING: Resource.Condition.Status.FALSE,
        },
        resource_kind=ClusterVersion,
        condition_key1="type",
        condition_key2="status",
        polling_interval=30,
        exceptions_dict={
            **BASE_EXCEPTIONS_DICT,
            NotFoundError: [],
            ResourceNotFoundError: [],
        },
    )


def wait_for_cluster_version_state_and_version(cluster_version, target_ocp_version):
    def _cluster_version_state_and_version(_cluster_version, _target_ocp_version):
        cluster_version_status_history = _cluster_version.instance.status.history[0]
        LOGGER.info(f"clusterversion status.histroy: {cluster_version_status_history}")
        return (
            cluster_version_status_history.state == _cluster_version.Status.COMPLETED
            and cluster_version_status_history.version == target_ocp_version
        )

    try:
        for sample in TimeoutSampler(
            wait_timeout=TIMEOUT_180MIN,
            sleep=10,
            func=_cluster_version_state_and_version,
            _cluster_version=cluster_version,
            _target_ocp_version=target_ocp_version,
        ):
            if sample:
                return

    except TimeoutExpiredError:
        LOGGER.error(
            "Timeout reached while upgrading OCP. "
            f"clusterversion conditions: {cluster_version.instance.status.conditions}"
        )
        data_collector_dict = get_data_collector_dict()
        collect_resources_yaml_instance(
            resources_to_collect=[ClusterOperator],
            base_directory=data_collector_dict["data_collector_base_directory"],
        )
        raise


def verify_upgrade_ocp(admin_client, target_ocp_version, machine_config_pools_list):
    wait_for_cluster_version_state_and_version(
        cluster_version=get_clusterversion(dyn_client=admin_client),
        target_ocp_version=target_ocp_version,
    )
    wait_for_mcp_update_completion(machine_config_pools_list=machine_config_pools_list)

    wait_for_cluster_version_stable_conditions(
        admin_client=admin_client,
    )


def get_all_cnv_alerts(prometheus, file_name, base_directory):
    cnv_alerts = []
    alerts_fired = prometheus.alerts["data"].get("alerts")
    for alert in alerts_fired:
        if (
            alert["labels"].get("kubernetes_operator_part_of")
            and alert["labels"]["kubernetes_operator_part_of"] == "kubevirt"
        ):
            cnv_alerts.append(alert)

    write_to_file(
        base_directory=base_directory,
        file_name=file_name,
        content=json.dumps(cnv_alerts),
    )
    return cnv_alerts


def get_alerts_fired_during_upgrade(prometheus, before_upgrade_alerts, base_directory):
    after_upgrade_alerts = get_all_cnv_alerts(
        prometheus=prometheus,
        file_name="after_upgrade_alerts.json",
        base_directory=base_directory,
    )
    before_upgrade_alert_names = [
        alert["labels"]["alertname"] for alert in before_upgrade_alerts
    ]
    fired_during_upgrade = []
    for alert in after_upgrade_alerts:
        alert_name = alert["labels"]["alertname"]
        if alert_name in before_upgrade_alert_names:
            continue
        LOGGER.info(
            f"Alert {alert_name}, state: {alert['state']} fired during upgrade."
        )
        fired_during_upgrade.append(alert)
    return fired_during_upgrade


def process_alerts_fired_during_upgrade(prometheus, fired_alerts_during_upgrade):
    pending_alerts = []
    for alert in fired_alerts_during_upgrade:
        if alert["state"] == "pending":
            pending_alerts.append(alert["labels"]["alertname"])

    LOGGER.info(f"Pending alerts: {pending_alerts}")
    if pending_alerts:
        # wait for the pending alerts to be fired within 10 minutes, since pending alerts would be part of alerts fired
        # during upgrade, we don't need to fail, if pending alerts did not fire.
        wait_for_pending_alerts_to_fire(
            prometheus=prometheus, pending_alerts=pending_alerts
        )


def wait_for_pending_alerts_to_fire(pending_alerts, prometheus):
    def _get_fired_alerts(_all_alerts, _alert_list):
        current_firing_alerts = []
        current_pending_alerts = []
        for _alert in _all_alerts:
            if (
                not _alert["labels"].get("kubernetes_operator_part_of")
                or _alert["labels"]["kubernetes_operator_part_of"] != "kubevirt"
            ):
                continue
            _alert_name = _alert["labels"]["alertname"]
            if _alert["state"] == FIRING_STATE:
                current_firing_alerts.append(_alert_name)
            elif _alert["state"] == "pending":
                current_pending_alerts.append(_alert_name)

        not_fired = [
            _alert for _alert in _alert_list if _alert not in current_firing_alerts
        ]
        LOGGER.warning(
            f"Out of {_alert_list}, following alerts are still not fired: {not_fired}"
        )
        return not_fired

    _pending_alerts = pending_alerts
    sampler = TimeoutSampler(
        wait_timeout=TIMEOUT_10MIN,
        sleep=2,
        func=_get_fired_alerts,
        _all_alerts=prometheus.alerts["data"].get("alerts"),
        _alert_list=_pending_alerts,
    )
    try:
        for sample in sampler:
            if not sample:
                return
            _pending_alerts = sample
            LOGGER.warning(f"Waiting on alerts: {_pending_alerts}")
    except TimeoutExpiredError:
        LOGGER.error(
            f"Out of {pending_alerts}, following alerts did not get to {FIRING_STATE}: {_pending_alerts}"
        )
