import inspect
import logging
import re

from benedict import benedict
from ocp_resources.deployment import Deployment
from ocp_resources.installplan import InstallPlan
from ocp_resources.network_addons_config import NetworkAddonsConfig
from ocp_resources.operator_condition import OperatorCondition
from ocp_resources.resource import Resource
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from ocp_utilities.data_collector import collect_resources_yaml_instance
from ocp_utilities.infra import cluster_resource
from openshift.dynamic.exceptions import ConflictError
from pytest_testconfig import py_config

from utilities.constants import (
    HCO_SUBSCRIPTION,
    TIMEOUT_10MIN,
    TIMEOUT_30MIN,
    TIMEOUT_40MIN,
)
from utilities.data_collector import get_data_collector_dict
from utilities.infra import get_subscription
from utilities.virt import VirtualMachineForTests, fedora_vm_body


NUM_TEST_VMS = 3
LOGGER = logging.getLogger(__name__)


def wait_for_operator_condition(dyn_client, hco_namespace, name, upgradable):
    LOGGER.info(f"Wait for the operator condition. Name:{name} Upgradable:{upgradable}")
    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_30MIN,
        sleep=1,
        func=cluster_resource(OperatorCondition).get,
        dyn_client=dyn_client,
        namespace=hco_namespace,
        name=name,
    )
    try:
        for sample in samples:
            for operator_condition in sample:
                operator_spec_condition = operator_condition.instance.spec.conditions
                if operator_spec_condition:
                    upgradeable_condition = next(
                        (
                            condition
                            for condition in operator_spec_condition
                            if condition.type == "Upgradeable"
                        ),
                        None,
                    )
                    if (
                        upgradeable_condition is not None
                        and upgradeable_condition.status == str(upgradable)
                    ):
                        return operator_condition
                else:
                    LOGGER.warning(
                        f"Waiting for hco operator to update spec.conditions of OperatorCondition: {name}"
                    )
    except TimeoutExpiredError:
        LOGGER.error(
            f"timeout waiting for operator version: name={name}, upgradable:{upgradable}"
        )
        raise


def wait_for_install_plan(dyn_client, hco_namespace, hco_target_version):
    install_plan_sampler = TimeoutSampler(
        wait_timeout=TIMEOUT_40MIN,
        sleep=1,
        func=cluster_resource(InstallPlan).get,
        exceptions_dict={
            ConflictError: []
        },  # Ignore ConflictError during install plan reconciliation
        dyn_client=dyn_client,
        hco_namespace=hco_namespace,
        hco_target_version=hco_target_version,
    )
    subscription = get_subscription(
        admin_client=dyn_client,
        namespace=hco_namespace,
        subscription_name=HCO_SUBSCRIPTION,
    )
    install_plan_name_in_subscription = None
    try:
        for install_plan_samples in install_plan_sampler:
            # wait for the install plan to be created and updated in the subscription.
            install_plan_name_in_subscription = getattr(
                subscription.instance.status.installplan, "name", None
            )
            for ip in install_plan_samples:
                # If we find a not-approved install plan that is associated with production catalogsource, we need
                # to delete it. Deleting the install plan associated with production catalogsource, would cause
                # install plan associated with custom catalog source to generate. Upgrade automation is supposed to
                # upgrade cnv using custom catalogsource, to a specified version. Approving install plan associated
                # with the production catalogsource would also lead to failure as production catalogsource has been
                # disabled at this point.
                if (
                    not ip.instance.spec.approved
                    and ip.instance.status.bundleLookups[0]["catalogSourceRef"]["name"]
                    == "redhat-operators"
                ):
                    ip.delete(wait=True)
                    continue
                if (
                    hco_target_version == ip.instance.spec.clusterServiceVersionNames[0]
                    and ip.name == install_plan_name_in_subscription
                ):
                    return ip
                LOGGER.info(
                    f"Subscription: {subscription.name}, is associated with install plan:"
                    f" {install_plan_name_in_subscription}"
                )
    except TimeoutExpiredError:
        LOGGER.error(
            f"timeout waiting for target install plan: version={hco_target_version}, "
            f"subscription install plan: {install_plan_name_in_subscription}"
        )
        if py_config.get("data_collector"):
            data_collector_dict = get_data_collector_dict()
            collect_resources_yaml_instance(
                resources_to_collect=[InstallPlan],
                base_directory=data_collector_dict["data_collector_base_directory"],
            )
        raise


def get_deployment_by_name(admin_client, namespace_name, deployment_name):
    """
    Gets a deployment object by name

    Args:
        admin_client (DynamicClient): a DynamicClient object
        namespace_name (str): name of the associated namespace
        deployment_name (str): Name of the deployment

    Returns:
        Deployment: Deployment object
    """
    for dp in cluster_resource(Deployment).get(
        dyn_client=admin_client,
        namespace=namespace_name,
        name=deployment_name,
    ):
        return dp


def get_network_addon_config(admin_client):
    """
    Gets NetworkAddonsConfig object

    Args:
        admin_client (DynamicClient): a DynamicClient object

    Returns:
        Generator of NetworkAddonsConfig: Generator of NetworkAddonsConfig
    """
    for nao in cluster_resource(NetworkAddonsConfig).get(
        dyn_client=admin_client, name="cluster"
    ):
        return nao


def wait_for_spec_change(expected, get_spec_func, base_path):
    """
    Waits for spec values to get propagated

    Args:
        expected (dict): dictionary of values that would be used to update hco cr
        get_spec_func (function): function to fetch current spec dictionary
        base_path (list): list of associated keys for a given kind
    """

    def _compare_spec_values(_expected, _get_spec_func, _base_path):
        LOGGER.info(
            f"Expected: {_expected}, basepath: {_base_path} {benedict(_get_spec_func())}"
        )
        spec_dict = benedict(_get_spec_func()).get(base_path)
        LOGGER.info(f"spec: {spec_dict}")
        return (
            sorted(expected.items()) == sorted(spec_dict.items()),
            f"Compare mismatch: expected={expected} spec_dict={spec_dict}",
        )

    samplers = TimeoutSampler(
        wait_timeout=60,
        sleep=5,
        func=_compare_spec_values,
        _expected=expected,
        _get_spec_func=get_spec_func,
        _base_path=base_path,
    )
    try:
        for compare_result in samplers:
            if _compare_spec_values:
                LOGGER.info(
                    f"{get_function_name(function_name=get_spec_func)}: Found expected spec values: '{expected}'"
                )
                return True

    except TimeoutExpiredError:
        LOGGER.error(
            f"{get_function_name(function_name=get_spec_func)}: Timed out waiting for CR with expected spec."
            f" spec: '{expected}' diff:'{compare_result}'"
        )
        raise


def get_function_name(function_name):
    """
    Return the text of the source code for a function

    Args:
        function_name (function object): function object

    Returns:
        str: name of the function
    """
    return inspect.getsource(function_name).split("(")[0].split(" ")[-1]


def create_vms(
    name_prefix, namespace_name, vm_count=NUM_TEST_VMS, client=None, ssh=True
):
    """
    Create n number of fedora vms.

    Args:
        name_prefix (str): prefix to be used to name virtualmachines
        namespace_name (str): Namespace to be used for vm creation
        vm_count (int): Number of vms to be created
        client (DynamicClient): DynamicClient object
        ssh (bool): enable SSH on the VM

    Returns:
        list: List of VirtualMachineForTests
    """
    vms_list = []
    for idx in range(vm_count):
        vm_name = f"{name_prefix}-{idx}"
        with cluster_resource(VirtualMachineForTests)(
            name=vm_name,
            namespace=namespace_name,
            body=fedora_vm_body(name=vm_name),
            teardown=False,
            running=True,
            ssh=ssh,
            client=client,
        ) as vm:
            vms_list.append(vm)
    return vms_list


def get_resource_container_env_image_mismatch(container):
    return [
        env_dict
        for env_dict in container.get("env", [])
        if "image" in env_dict["name"].lower()
        and env_dict.get("value")
        and not re.match(
            rf"NOT_AVAILABLE|{Resource.ApiGroup.IMAGE_REGISTRY}",
            env_dict.get("value"),
        )
    ]


def wait_for_cr_labels_change(expected_value, component):
    """
    Waits for CR metadata.labels to reach expected values

    Args:
        expected_value (dict): expected value for metadata.labels
        component (Resource): Resource object

    Returns:
        bool: Indicates a match is found

    Raises:
        TimeoutExpiredError: If the CR's metadata.labels does not match with expected value.
    """
    samplers = TimeoutSampler(
        wait_timeout=TIMEOUT_10MIN,
        sleep=5,
        func=lambda: component.instance.metadata.labels,
    )
    label = None
    try:
        for label in samplers:
            if label == expected_value:
                LOGGER.info(
                    f"For {component.name}: Found expected spec values: '{expected_value}'"
                )
                return True

    except TimeoutExpiredError:
        LOGGER.error(
            f"{component.name}: Timed out waiting for CR labels to reach expected value: '{expected_value}'"
            f" current value:'{label}'"
        )
        raise
