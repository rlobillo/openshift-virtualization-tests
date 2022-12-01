# TODO: Remove ### unused_code: ignore ### from function docstring once it's used.

import logging
import os
import shlex
from contextlib import contextmanager
from pprint import pformat

from ocp_resources.catalog_source import CatalogSource
from ocp_resources.cluster_service_version import ClusterServiceVersion
from ocp_resources.image_content_source_policy import ImageContentSourcePolicy
from ocp_resources.installplan import InstallPlan
from ocp_resources.machine_config_pool import MachineConfigPool
from ocp_resources.namespace import Namespace
from ocp_resources.node import Node
from ocp_resources.operator_group import OperatorGroup
from ocp_resources.operator_hub import OperatorHub
from ocp_resources.pod import Pod
from ocp_resources.resource import Resource, ResourceEditor
from ocp_resources.subscription import Subscription
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from ocp_utilities.data_collector import collect_resources_yaml_instance
from openshift.dynamic.exceptions import ResourceNotFoundError
from pytest_testconfig import config as py_config

import utilities.infra
from utilities.constants import (
    BASE_EXCEPTIONS_DICT,
    ICSP_FILE,
    TIMEOUT_5MIN,
    TIMEOUT_10MIN,
    TIMEOUT_15MIN,
    TIMEOUT_20MIN,
    TIMEOUT_75MIN,
)
from utilities.data_collector import collect_mcp_information, get_data_collector_dict


LOGGER = logging.getLogger(__name__)


def create_icsp_command(image, source_url, folder_name, pull_secret=None):
    base_command = f"oc adm catalog mirror {image} {source_url} --manifests-only --to-manifests {folder_name} "
    if pull_secret:
        base_command = f"{base_command} --registry-config={pull_secret}"
    return base_command


def generate_icsp_file(folder_name, command):
    rc, _, _ = utilities.infra.run_command(
        command=shlex.split(command),
        verify_stderr=False,
    )
    assert rc

    icsp_file_path = os.path.join(folder_name, ICSP_FILE)
    assert os.path.isfile(
        icsp_file_path
    ), f"ICSP file does not exist in path {icsp_file_path}"

    return icsp_file_path


def create_icsp_from_file(icsp_file_path):
    LOGGER.info(f"Creating icsp using file: {icsp_file_path}")
    rc, _, _ = utilities.infra.run_command(
        command=shlex.split(f"oc create -f {icsp_file_path}"), verify_stderr=False
    )
    assert rc


def delete_existing_icsp(
    admin_client,
    name,
):
    LOGGER.info("Deleting ImageContentSourcePolicy.")
    for icsp in ImageContentSourcePolicy.get(dyn_client=admin_client):
        icsp_name = icsp.name
        if icsp_name.startswith(name):
            LOGGER.info(f"Deleting ICSP {icsp_name}.")
            icsp.delete(wait=True)


def get_mcps_with_matching_status_conditions(condition_type, machine_config_pools_list):
    return {
        mcp.name
        for mcp in machine_config_pools_list
        for condition in mcp.instance.status.conditions
        if condition["type"] == condition_type
        and condition["status"] == Resource.Condition.Status.TRUE
    }


def wait_for_machine_config_pools_condition_status(
    machine_config_pools_list, condition_type, timeout
):
    mcps_to_check = {mcp.name for mcp in machine_config_pools_list}
    LOGGER.info(
        f"Waiting for mcps {mcps_to_check} to reach condition: desired={condition_type}"
    )
    samplers = TimeoutSampler(
        wait_timeout=timeout,
        sleep=5,
        func=get_mcps_with_matching_status_conditions,
        exceptions_dict=BASE_EXCEPTIONS_DICT,
        condition_type=condition_type,
        machine_config_pools_list=machine_config_pools_list,
    )
    found_mcp_in_status = set()
    not_matching_mcp = set()
    try:
        for sample in samplers:
            found_mcp_in_status.update(sample)
            not_matching_mcp = mcps_to_check - found_mcp_in_status
            if not not_matching_mcp:
                return
    except TimeoutExpiredError:
        LOGGER.error(
            f"Out of mcps {mcps_to_check}, followings {not_matching_mcp} were not at desired "
            f"condition {condition_type} before timeout. "
            f"current mcp status={ {mcp.name: mcp.instance.status.conditions for mcp in machine_config_pools_list}}"
        )
        if py_config.get("data_collector"):
            data_collector_dict = get_data_collector_dict()
            collect_resources_yaml_instance(
                resources_to_collect=[MachineConfigPool, Node],
                base_directory=data_collector_dict["data_collector_base_directory"],
            )
            collect_mcp_information()
        raise


def wait_for_machine_config_pool_updated_condition(machine_config_pools_list):
    LOGGER.info("Wait for mcp update to end.")
    try:
        wait_for_machine_config_pools_condition_status(
            machine_config_pools_list=machine_config_pools_list,
            condition_type=MachineConfigPool.Status.UPDATED,
            timeout=TIMEOUT_75MIN,
        )
    except TimeoutExpiredError:
        if py_config.get("data_collector"):
            collect_mcp_information()
        raise


def wait_for_machine_config_pool_updating_condition(machine_config_pools_list):
    LOGGER.info("Wait for mcp update to start.")
    try:
        wait_for_machine_config_pools_condition_status(
            machine_config_pools_list=machine_config_pools_list,
            condition_type=MachineConfigPool.Status.UPDATING,
            timeout=TIMEOUT_15MIN,
        )
    except TimeoutExpiredError:
        # In cases where the MCP transitions quickly and the UPDATING status is missed
        updated_mcps = get_mcps_with_matching_status_conditions(
            machine_config_pools_list=machine_config_pools_list,
            condition_type=MachineConfigPool.Status.UPDATED,
        )
        if updated_mcps:
            LOGGER.info(
                f"Following mcp(s)={updated_mcps} are already in {MachineConfigPool.Status.UPDATED} condition: "
            )
        else:
            if py_config.get("data_collector"):
                collect_mcp_information()
            raise


def get_machine_config_pool_by_name(mcp_name):
    mcp = utilities.infra.cluster_resource(MachineConfigPool)(name=mcp_name)
    if mcp.exists:
        return mcp
    raise ResourceNotFoundError(f"OperatorHub {mcp_name} not found")


def get_operator_hub():
    operator_hub_name = "cluster"
    operator_hub = utilities.infra.cluster_resource(OperatorHub)(name=operator_hub_name)
    if operator_hub.exists:
        return operator_hub
    raise ResourceNotFoundError(f"OperatorHub {operator_hub_name} not found")


@contextmanager
def disable_default_sources_in_operatorhub(admin_client):
    operator_hub = get_operator_hub()
    LOGGER.info("Disable default sources in operatorhub.")
    with ResourceEditor(
        patches={operator_hub: {"spec": {"disableAllDefaultSources": True}}}
    ) as edited_source:
        # wait for all the catalogsources to disappear:
        sources = operator_hub.instance.status.sources
        for catalog_source_name in [
            catalog_source["name"] for catalog_source in sources
        ]:
            wait_for_catalog_source_disabled(catalog_name=catalog_source_name)
        yield edited_source


def get_catalog_source(catalog_name):
    market_place_namespace = py_config["marketplace_namespace"]
    catalog_source = utilities.infra.cluster_resource(CatalogSource)(
        namespace=market_place_namespace, name=catalog_name
    )
    if catalog_source.exists:
        return catalog_source
    LOGGER.warning(
        f"CatalogSource {catalog_name} not found in namespace: {market_place_namespace}"
    )


def wait_for_catalog_source_disabled(catalog_name):
    LOGGER.info(f"Wait for catalogsource {catalog_name} to be disabled.")
    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_5MIN,
        sleep=10,
        func=get_catalog_source,
        catalog_name=catalog_name,
    )
    try:
        for catalog_source in samples:
            if not catalog_source:
                return
    except TimeoutExpiredError:
        LOGGER.error(f"Catalogsource {catalog_name} did not get disabled.")
        raise


def create_catalog_source(
    catalog_name,
    image,
    display_name="OpenShift Virtualization Index Image",
):
    LOGGER.info(f"Create catalog source {catalog_name}")
    catalog_source = utilities.infra.cluster_resource(CatalogSource)(
        name=catalog_name,
        namespace=py_config["marketplace_namespace"],
        display_name=display_name,
        source_type="grpc",
        image=image,
        publisher="Red Hat",
    )
    catalog_source.deploy(wait=True)
    return catalog_source


def wait_for_catalogsource_ready(admin_client, catalog_name):
    """
    ### unused_code: ignore ###
    """
    LOGGER.info(
        f"Wait for pods associated with catalog source: {catalog_name} to get to 'Running' state"
    )

    def _get_catalog_source_pods_not_running():
        not_running = [
            _pod.name
            for _pod in utilities.infra.get_pods(
                dyn_client=admin_client,
                namespace=utilities.infra.cluster_resource(Namespace)(
                    name=py_config["marketplace_namespace"]
                ),
                label=f"olm.catalogSource={catalog_name}",
            )
            if _pod.instance.status.phase != Pod.Status.RUNNING
        ]
        LOGGER.info(f"Not running pods: {not_running}")
        return not_running

    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_5MIN,
        sleep=10,
        func=_get_catalog_source_pods_not_running,
    )
    not_running_pod = None
    try:
        for not_running_pod in samples:
            if not not_running_pod:
                return
    except TimeoutExpiredError:
        LOGGER.error(
            f"Pods {not_running_pod} associated with {catalog_name} did not go to running state."
        )
        raise


def create_operator_group(operator_group_name, namespace_name):
    LOGGER.info(
        f"Create operatorgroup {operator_group_name} in namespace {namespace_name}"
    )
    operator_group = utilities.infra.cluster_resource(OperatorGroup)(
        name=operator_group_name,
        namespace=namespace_name,
        target_namespaces=[namespace_name],
    )
    operator_group.deploy(wait=True)
    return operator_group


def create_subscription(
    subscription_name,
    package_name,
    namespace_name,
    catalogsource_name,
    channel_name="stable",
    install_plan_approval="Automatic",
):
    """
    ### unused_code: ignore ###
    """
    LOGGER.info(
        f"Create subscription {subscription_name} on namespace {namespace_name}"
    )
    subscription = utilities.infra.cluster_resource(Subscription)(
        name=subscription_name,
        package_name=package_name,
        namespace=namespace_name,
        channel=channel_name,
        install_plan_approval=install_plan_approval,
        source=catalogsource_name,
        source_namespace=py_config["marketplace_namespace"],
    )
    subscription.deploy(wait=True)
    return subscription


def approve_install_plan(install_plan):
    ResourceEditor(patches={install_plan: {"spec": {"approved": True}}}).update()
    install_plan.wait_for_status(
        status=install_plan.Status.COMPLETE, timeout=TIMEOUT_20MIN
    )


def get_install_plan_from_subscription(subscription):
    """
    ### unused_code: ignore ###
    """
    LOGGER.info(
        f"Wait for install plan to be created in subscription {subscription.name}."
    )
    install_plan_sampler = TimeoutSampler(
        wait_timeout=TIMEOUT_5MIN,
        sleep=30,
        func=lambda: subscription.instance.status.installplan,
    )
    try:
        for install_plan in install_plan_sampler:
            if install_plan:
                LOGGER.info(f"Install plan found {install_plan}.")
                return install_plan["name"]
    except TimeoutExpiredError:
        LOGGER.error(
            f"Subscription: {subscription.name}, did not get updated with install plan: "
            f"{pformat(subscription)}"
        )
        raise


def wait_for_operator_install(
    admin_client, install_plan_name, namespace_name, subscription_name
):
    """
    ### unused_code: ignore ###
    """
    install_plan = utilities.infra.cluster_resource(InstallPlan)(
        client=admin_client,
        name=install_plan_name,
        namespace=namespace_name,
    )
    install_plan.wait_for_status(
        status=install_plan.Status.COMPLETE, timeout=TIMEOUT_5MIN
    )
    wait_for_csv_successful_state(
        admin_client=admin_client,
        namespace_name=namespace_name,
        subscription_name=subscription_name,
    )


def wait_for_csv_successful_state(admin_client, namespace_name, subscription_name):
    subscription = utilities.infra.cluster_resource(Subscription)(
        name=subscription_name, namespace=namespace_name
    )
    if subscription.exists:
        csv = utilities.infra.get_csv_by_name(
            csv_name=subscription.instance.status.installedCSV,
            admin_client=admin_client,
            namespace=namespace_name,
        )
        csv.wait_for_status(
            status=ClusterServiceVersion.Status.SUCCEEDED, timeout=TIMEOUT_10MIN
        )
        return
    raise ResourceNotFoundError(
        f"Subscription {subscription_name} not found in namespace: {namespace_name}"
    )


def wait_for_mcp_update_completion(machine_config_pools_list):
    wait_for_machine_config_pool_updating_condition(
        machine_config_pools_list=machine_config_pools_list
    )
    wait_for_machine_config_pool_updated_condition(
        machine_config_pools_list=machine_config_pools_list
    )


def create_operator(operator_class, operator_name, namespace_name=None):
    """
    ### unused_code: ignore ###
    """
    if namespace_name:
        operator = operator_class(name=operator_name, namespace=namespace_name)
    else:
        operator = operator_class(name=operator_name)
    if operator.exists:
        LOGGER.warning(
            f"Operator: {operator_name} already exists in namespace: {namespace_name}"
        )
        return
    LOGGER.info(
        f"Operator: {operator_name} is getting deployed in namespace: {namespace_name}"
    )
    operator.deploy(wait=True)
    return operator


def wait_for_package_manifest_to_exist(dyn_client, cr_name, catalog_name):
    LOGGER.info(
        f"Wait for package manifest creation for {cr_name} associated with catalog source: {catalog_name}"
    )
    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_10MIN,
        sleep=10,
        func=utilities.infra.get_raw_package_manifest,
        admin_client=dyn_client,
        name=cr_name,
        catalog_source=catalog_name,
    )
    try:
        for sample in samples:
            if sample:
                return
    except TimeoutExpiredError:
        LOGGER.error(
            f"{cr_name} package associated with {catalog_name} did not get created"
        )
        raise


def update_image_in_catalog_source(dyn_client, image, catalog_source_name, cr_name):
    catalog = get_catalog_source(catalog_name=catalog_source_name)
    if catalog:
        LOGGER.info(f"Updating {catalog_source_name} image to {image}")
        ResourceEditor(patches={catalog: {"spec": {"image": image}}}).update()
    else:
        LOGGER.info(f"Creating CatalogSource {catalog_source_name} with image {image}.")
        create_catalog_source(
            catalog_name=catalog_source_name,
            image=image,
        )
        LOGGER.info(
            f"Waiting for {cr_name} packagemanifest associated with {catalog_source_name} to appear"
        )
        wait_for_package_manifest_to_exist(
            dyn_client=dyn_client, catalog_name=catalog_source_name, cr_name=cr_name
        )


def update_subscription_channel_and_source(
    subscription, subscription_channel, subscription_source
):
    LOGGER.info(
        f"Update subscription {subscription.name} channel to {subscription_channel}, source to {subscription_source}"
    )
    ResourceEditor(
        {
            subscription: {
                "spec": {
                    "channel": subscription_channel,
                    "source": subscription_source,
                }
            }
        }
    ).update()
