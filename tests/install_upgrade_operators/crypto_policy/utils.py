import logging

from benedict import benedict
from ocp_resources.cluster_operator import ClusterOperator
from ocp_resources.resource import Resource
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from ocp_utilities.infra import cluster_resource

from tests.install_upgrade_operators.constants import KEY_PATH_SEPARATOR
from utilities.constants import DEFAULT_RESOURCE_CONDITIONS, TIMEOUT_2MIN, TIMEOUT_15MIN


LOGGER = logging.getLogger(__name__)


def get_resource_crypto_policy(admin_client, resource, name, key_name, namespace=None):
    """
    This function is used to get crypto policy settings associated with a resource

    Args:
        admin_client (DynamicClient): OCP Client to use.
        resource (Resource): Resource kind
        name (str): name of a resource
        key_name (str): full key path with separator
        namespace (str, optional): namespace for the resource

    Returns:
        dict: crypto policy settings value associated with the resource
    """
    kwargs = {"client": admin_client, "name": name}
    if namespace:
        kwargs["namespace"] = namespace
    resource_obj = cluster_resource(resource)(**kwargs)
    return benedict(
        resource_obj.instance.to_dict()["spec"], keypath_separator=KEY_PATH_SEPARATOR
    ).get(key_name)


def wait_for_crypto_policy_update(
    admin_client, resource, resource_namespace, resource_name, key_name, expected_policy
):

    sampler = TimeoutSampler(
        wait_timeout=TIMEOUT_2MIN,
        sleep=2,
        func=get_resource_crypto_policy,
        admin_client=admin_client,
        resource=resource,
        namespace=resource_namespace,
        name=resource_name,
        key_name=key_name,
    )
    sample = None
    try:
        for sample in sampler:
            # TODO: remove log message once the test and feature deemed to be stable
            LOGGER.info(
                f"{resource_name} actual: {sample}, expected: {expected_policy}"
            )
            if sample and sorted(sample.items()) == sorted(expected_policy.items()):
                return
    except TimeoutExpiredError:
        error_message = (
            f"For resource {resource} {resource_name}, expected policy {expected_policy},"
            f" did not match {sample} "
        )
        LOGGER.error(error_message)
        return error_message


def get_cluster_operator_status_conditions(admin_client, operator_conditions=None):
    operator_conditions = operator_conditions or DEFAULT_RESOURCE_CONDITIONS
    cluster_operator_status = {}
    for cluster_operator in list(
        cluster_resource(ClusterOperator).get(dyn_client=admin_client)
    ):
        operator_name = cluster_operator.name
        cluster_operator_status[operator_name] = {}
        for condition in cluster_operator.instance.get("status", {}).get(
            "conditions", []
        ):
            if condition["type"] in operator_conditions:
                if (
                    operator_name == "console"
                    and condition["type"] == Resource.Condition.DEGRADED
                    and condition["status"]
                    and "ConsoleNotificationSyncDegraded" in condition["message"]
                ):
                    cluster_operator_status[operator_name][
                        condition["type"]
                    ] = Resource.Condition.Status.FALSE
                else:
                    cluster_operator_status[operator_name][
                        condition["type"]
                    ] = condition["status"]

    return cluster_operator_status


def get_failed_cluster_operator(admin_client):
    cluster_operators_status_conditions = get_cluster_operator_status_conditions(
        admin_client=admin_client
    )
    failed_operators = {}
    for cluster_operator in cluster_operators_status_conditions:
        if sorted(
            cluster_operators_status_conditions[cluster_operator].items()
        ) != sorted(DEFAULT_RESOURCE_CONDITIONS.items()):
            LOGGER.info(
                f"{cluster_operator} current status condition: {cluster_operators_status_conditions[cluster_operator]}"
            )
            failed_operators[cluster_operator] = cluster_operators_status_conditions[
                cluster_operator
            ]
    return failed_operators


def wait_for_cluster_operator_stabilize(admin_client):
    # TODO: Once https://issues.redhat.com/browse/OCPBUGS-4011 is addressed, we would need to adjust the timeout
    # value to a more reasonable value. Currently reducing it, can make the cluster not usable/responsive
    sampler = TimeoutSampler(
        wait_timeout=TIMEOUT_15MIN,
        sleep=10,
        func=get_failed_cluster_operator,
        admin_client=admin_client,
    )
    consecutive_check = 0
    sample = None
    try:
        for sample in sampler:
            if not sample:
                LOGGER.info(f"Found stable cluster operator: {consecutive_check} time.")
                consecutive_check += 1
            else:
                LOGGER.info(
                    f"Following cluster operators are not yet stable: {sample}."
                )
                consecutive_check = 0
            if consecutive_check == 3:
                return

    except TimeoutExpiredError:
        LOGGER.error(f"Following cluster operators failed to stabilize: {sample}")
        if sample:
            raise
