import base64
import http
import io
import json
import logging
import os
import platform
import re
import shlex
import stat
import subprocess
import tarfile
import tempfile
import time
import zipfile
from configparser import ConfigParser
from contextlib import contextmanager
from pathlib import Path

import bugzilla
import kubernetes
import netaddr
import paramiko
import pytest
import requests
import urllib3
import yaml
from jira import JIRA
from kubernetes.client import ApiException
from ocp_resources.cluster_service_version import ClusterServiceVersion
from ocp_resources.cluster_version import ClusterVersion
from ocp_resources.console_cli_download import ConsoleCLIDownload
from ocp_resources.daemonset import DaemonSet
from ocp_resources.deployment import Deployment
from ocp_resources.hyperconverged import HyperConverged
from ocp_resources.namespace import Namespace
from ocp_resources.package_manifest import PackageManifest
from ocp_resources.pod import Pod
from ocp_resources.project import Project, ProjectRequest
from ocp_resources.resource import ResourceEditor
from ocp_resources.secret import Secret
from ocp_resources.subscription import Subscription
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from ocp_utilities.data_collector import write_to_file
from ocp_utilities.exceptions import NodeNotReadyError, NodeUnschedulableError
from ocp_utilities.infra import (
    assert_nodes_ready,
    assert_nodes_schedulable,
    cluster_resource,
)
from ocp_utilities.utils import run_command
from openshift.dynamic import DynamicClient
from openshift.dynamic.exceptions import NotFoundError, ResourceNotFoundError
from pytest_testconfig import config as py_config

import utilities.virt
from utilities.constants import (
    AUDIT_LOGS_PATH,
    HCO_CATALOG_SOURCE,
    OC_ADM_LOGS_COMMAND,
    OPENSHIFT_CONFIG_NAMESPACE,
    OPERATOR_NAME_SUFFIX,
    SANITY_TESTS_FAILURE,
    TIMEOUT_1MIN,
    TIMEOUT_2MIN,
    TIMEOUT_6MIN,
    TIMEOUT_10MIN,
)
from utilities.exceptions import UtilityPodNotFoundError
from utilities.storage import get_images_server_url


BUG_STATUS_CLOSED = ("VERIFIED", "ON_QA", "CLOSED", "RELEASE_PENDING")
JIRA_STATUS_CLOSED = ("closed", "done", "obsolete", "resolved")
NON_EXIST_URL = "https://noneexist.test"  # Use 'test' domain rfc6761
EXCLUDED_FROM_URL_VALIDATION = ("", NON_EXIST_URL)
INTERNAL_HTTP_SERVER_ADDRESS = "internal-http.cnv-tests-utilities"

LOGGER = logging.getLogger(__name__)


class OsDictNotFoundError(Exception):
    pass


class ClusterSanityError(Exception):
    def __init__(self, err_str):
        self.err_str = err_str

    def __str__(self):
        return self.err_str


def label_project(name, label, admin_client):
    ns = Namespace(client=admin_client, name=name)
    ResourceEditor({ns: {"metadata": {"labels": label}}}).update()


def create_ns(
    name,
    unprivileged_client=None,
    labels=None,
    admin_client=None,
    teardown=True,
    delete_timeout=TIMEOUT_6MIN,
):
    """
    For kubemacpool labeling opt-modes, provide kmp_vm_label and admin_client as admin_client
    """
    if not unprivileged_client:
        with cluster_resource(Namespace)(
            client=admin_client,
            name=name,
            label=labels,
            teardown=teardown,
            delete_timeout=delete_timeout,
        ) as ns:
            ns.wait_for_status(status=Namespace.Status.ACTIVE, timeout=TIMEOUT_2MIN)
            yield ns
    else:
        with cluster_resource(ProjectRequest)(
            name=name, client=unprivileged_client, teardown=teardown
        ):
            project = Project(
                name=name,
                client=unprivileged_client,
                teardown=teardown,
                delete_timeout=delete_timeout,
            )
            project.wait_for_status(project.Status.ACTIVE, timeout=TIMEOUT_2MIN)
            label_project(name=name, label=labels, admin_client=admin_client)
            yield project


def get_cert(server_type):
    path = os.path.join("tests/storage/cdi_import", py_config["servers"][server_type])
    with open(path, "r") as cert_content:
        data = cert_content.read()
    return data


class ClusterHosts:
    class Type:
        VIRTUAL = "virtual"
        PHYSICAL = "physical"


class MissingResourceException(Exception):
    def __init__(self, resource):
        self.resource = resource

    def __str__(self):
        return f"No resources of type {self.resource} were found. Please check the test environment setup."


class UrlNotFoundError(Exception):
    def __init__(self, url_request):
        self.url_request = url_request

    def __str__(self):
        return f"{self.url_request.url} not found. status code is: {self.url_request.status_code}"


class FileNotFoundInUrlError(Exception):
    def __init__(self, url_request, file_name):
        self.url_request = url_request
        self.file_name = file_name

    def __str__(self):
        return f"{self.file_name} not found in url {self.url_request.url}"


def validate_file_exists_in_url(url):
    base_url, file_name = url.rsplit("/", 1)
    response = requests.get(base_url, verify=False)
    if response.status_code != 200:
        raise UrlNotFoundError(url_request=response)

    if file_name not in str(response.content):
        raise FileNotFoundInUrlError(url_request=response, file_name=file_name)


def url_excluded_from_validation(url):
    # Negative URL test cases or internal http server
    return url in EXCLUDED_FROM_URL_VALIDATION or INTERNAL_HTTP_SERVER_ADDRESS in url


def get_schedulable_nodes_ips(nodes):
    return {node.name: node.internal_ip for node in nodes}


def camelcase_to_mixedcase(camelcase_str):
    # Utility to convert CamelCase to mixedCase
    # Example: Service type may be NodePort but in VM attributes.spec.ports it is nodePort
    return camelcase_str[0].lower() + camelcase_str[1:]


def get_admin_client():
    return DynamicClient(client=kubernetes.config.new_client_from_config())


def get_pod_by_name_prefix(dyn_client, pod_prefix, namespace, get_all=False):
    """
    Args:
        dyn_client (DynamicClient): OCP Client to use.
        pod_prefix (str): str or regex pattern.
        namespace (str): Namespace name.
        get_all (bool): Return all pods if True else only the first one.

    Returns:
        list or Pod: A list of all matching pods if get_all (empty list if no pods found) else only the first pod.
    """
    pods = [
        pod
        for pod in cluster_resource(Pod).get(dyn_client=dyn_client, namespace=namespace)
        if re.match(pod_prefix, pod.name)
    ]
    if get_all:
        return pods  # Some negative cases check if no pods exists.
    elif pods:
        return pods[0]
    raise ResourceNotFoundError(f"A pod with the {pod_prefix} prefix does not exist")


def generate_namespace_name(file_path):
    return (file_path.strip(".py").replace("/", "-").replace("_", "-"))[-63:].split(
        "-", 1
    )[-1]


def generate_latest_os_dict(os_list):
    """
    Get latest os dict.

    Args:
        os_list (list): [<os-name>]_os_matrix - a list of dicts.

    Returns:
        dict: {Latest OS name: latest supported OS dict} else raises an exception.

    Raises:
        OsDictNotFoundError: If no os matched.
    """
    for os_dict in os_list:
        for os_version, os_values in os_dict.items():
            if os_values.get("latest_released"):
                return {os_version: os_values}

    raise OsDictNotFoundError(f"No OS is marked as 'latest_released': {os_list}")


def get_latest_os_dict_list(os_list):
    """
    Get latest os dict generated by 'generate_latest_os_dict()'
    This will extract the dict from `generate_latest_os_dict()` without the name key.

    Args:
        os_list (list): [rhel|windows|fedora]_os_matrix - a list of dicts

    Returns:
        list: List of oses dict [{latest supported OS dict}]
    """
    res = []
    for _os in os_list:
        res.append(list(generate_latest_os_dict(os_list=_os).values())[0])
    return res


def base64_encode_str(text):
    return base64.b64encode(text.encode()).decode()


def private_to_public_key(key):
    return paramiko.RSAKey.from_private_key_file(key).get_base64()


def name_prefix(name):
    return name.split(".")[0]


def authorized_key(private_key_path):
    return f"ssh-rsa {private_to_public_key(key=private_key_path)} root@exec1.rdocloud"


def get_connection_params(conf_file_name):
    conf_file = os.path.join(Path(".").resolve(), conf_file_name)
    parser = ConfigParser()
    # Open the file with the correct encoding
    parser.read(conf_file, encoding="utf-8")
    params_dict = {}
    for params in parser.items("DEFAULT"):
        params_dict[params[0]] = params[1]
    return params_dict


def get_bug(bug_id):
    bugzilla_connection_params = get_connection_params(conf_file_name="bugzilla.cfg")
    bzapi = bugzilla.Bugzilla(
        url=bugzilla_connection_params["bugzilla_url"],
        user=bugzilla_connection_params["bugzilla_username"],
        api_key=bugzilla_connection_params["bugzilla_api_key"],
    )
    return bzapi.getbug(objid=bug_id)


def get_jira_status(jira):
    jira_connection_params = get_connection_params(conf_file_name="jira.cfg")
    jira_connection = JIRA(
        token_auth=jira_connection_params["token"],
        options={"server": jira_connection_params["url"]},
    )
    return jira_connection.issue(id=jira).fields.status.name


def get_pods(dyn_client, namespace, label=None):
    return list(
        Pod.get(
            dyn_client=dyn_client,
            namespace=namespace.name,
            label_selector=label,
        )
    )


def wait_for_pods_deletion(pods):
    for pod in pods:
        pod.wait_deleted()


def wait_for_pods_running(admin_client, namespace, number_of_consecutive_checks=1):
    """
    Waits for all pods in a given namespace to reach Running/Completed state. To avoid catching all pods in running
    state too soon, use number_of_consecutive_checks with appropriate values.

    Args:
         admin_client(DynamicClient): Dynamic client
         namespace(Namespace): A namespace object
         number_of_consecutive_checks(int): Number of times to check for all pods in running state
    Raises:
        TimeoutExpiredError: Raises TimeoutExpiredError if any of the pods in the given namespace are not in Running
         state
    """

    def _get_not_running_pods():
        pods = list(Pod.get(dyn_client=admin_client, namespace=namespace.name))
        pods_not_running = []
        for pod in pods:
            try:
                # Waits for all pods in a given namespace to be in final healthy state(running/completed).
                # We also need to keep track of pods marked for deletion as not running. This would ensure any pod that
                # was spinned up in place of pod marked for deletion, reaches healthy state before end of this check
                if pod.instance.metadata.get(
                    "deletionTimestamp"
                ) or pod.instance.status.phase not in (
                    pod.Status.RUNNING,
                    pod.Status.SUCCEEDED,
                ):
                    pods_not_running.append({pod.name: pod.status})
            except (ResourceNotFoundError, NotFoundError):
                LOGGER.warning(
                    f"Ignoring pod {pod.name} that disappeared during cluster sanity check"
                )
                pods_not_running.append({pod.name: "Deleted"})
        return pods_not_running

    samples = TimeoutSampler(
        wait_timeout=120,
        sleep=1,
        func=_get_not_running_pods,
    )
    sample = None
    try:
        current_check = 0
        for sample in samples:
            if not sample:
                current_check += 1
                if current_check >= number_of_consecutive_checks:
                    return True
            else:
                current_check = 0
    except TimeoutExpiredError as exp:
        raise_multiple_exceptions(
            exceptions=[
                ClusterSanityError(
                    err_str=f"timeout waiting for all pods in namespace {namespace.name} to reach "
                    f"running state, following pods are in not running state: {sample}"
                ),
                exp,
            ]
        )


def get_daemonset_by_name(admin_client, daemonset_name, namespace_name):
    """
    Gets a daemonset object by name

    Args:
        admin_client (DynamicClient): a DynamicClient object
        daemonset_name (str): Name of the daemonset
        namespace_name (str): Name of the associated namespace

    Returns:
        Daemonset: Daemonset object
    """
    daemon_set = DaemonSet(
        client=admin_client,
        namespace=namespace_name,
        name=daemonset_name,
    )
    if daemon_set.exists:
        return daemon_set
    raise ResourceNotFoundError(
        f"Daemonset: {daemonset_name} not found in namespace: {namespace_name}"
    )


def wait_for_consistent_resource_conditions(
    dynamic_client,
    expected_conditions,
    resource_kind,
    condition_key1="type",
    condition_key2="status",
    namespace=None,
    total_timeout=TIMEOUT_10MIN,
    polling_interval=5,
    consecutive_checks_count=10,
    exceptions_dict=None,
):
    """This function awaits certain conditions of a given resource_kind (HCO, CSV, etc.).

    Using TimeoutSampler loop and poll the CR (of the resource_kind type) and attempt to match the expected conditions
    against the actual conditions found in the CR.
    Since the conditions statuses might change, we use consecutive checks in order to have consistent results (stable),
    thereby ascertaining that the expected conditions are met over time.

    Args:
        dynamic_client (DynamicClient): admin client
        namespace (str, default: None): resource namespace. Not needed for cluster-scoped resources.
        expected_conditions (dict): a dict comprises expected conditions to meet, for example:
            {<condition key's value>: <condition key's value>,
            Resource.Condition.AVAILABLE: Resource.Condition.Status.TRUE,}
        resource_kind (Resource): (e.g. HyperConverged, ClusterServiceVersion)
        condition_key1 (str): the key of the first condition in the actual resource_kind (e.g. type, reason, status)
        condition_key2 (str): the key of the second condition in the actual resource_kind (e.g. type, reason, status)
        total_timeout (int): total timeout to wait for (seconds)
        polling_interval (int): the time to sleep after each iteration (seconds)
        consecutive_checks_count (int): the number of repetitions for the status check to make sure the transition is
        done.
            The default value for this argument is not absolute, and there are situations in which it should be higher
            in order to ascertain the consistency of the Ready status.
            Possible situations:
            1. the resource is in a Ready status, because the process (that should cause
            the change in its state) has not started yet.
            2. some components are in Ready status, but others have not started the process yet.
        exceptions_dict: TimeoutSampler exceptions_dict

    Raises:
        TimeoutExpiredError: raised when expected conditions are not met within the timeframe
    """
    samples = TimeoutSampler(
        wait_timeout=total_timeout,
        sleep=polling_interval,
        func=lambda: list(
            resource_kind.get(
                dyn_client=dynamic_client,
                namespace=namespace,
            )
        ),
        exceptions_dict=exceptions_dict,
    )
    current_check = 0
    actual_conditions = {}
    LOGGER.info(
        f"Waiting for resource to stabilize: resource_kind={resource_kind.__name__} conditions={expected_conditions} "
        f"sleep={total_timeout} consecutive_checks_count={consecutive_checks_count}"
    )
    try:
        for sample in samples:
            status_conditions = sample[0].instance.get("status", {}).get("conditions")
            if status_conditions:
                actual_conditions = {
                    condition[condition_key1]: condition[condition_key2]
                    for condition in status_conditions
                    if condition[condition_key1] in expected_conditions
                }
                if actual_conditions == expected_conditions:
                    current_check += 1
                    if current_check >= consecutive_checks_count:
                        return
                else:
                    current_check = 0

    except TimeoutExpiredError:
        LOGGER.error(
            f"Timeout expired meeting conditions for resource: resource={resource_kind.kind} "
            f"expected_conditions={expected_conditions} status_conditions={actual_conditions}"
        )
        raise


def raise_multiple_exceptions(exceptions):
    """Raising multiple exceptions

    To be used when multiple exceptions need to be raised, for example when using TimeoutSampler,
    and additional information should be added (so it is viewable in junit report).
    Example:
        except TimeoutExpiredError as exp:
            raise_multiple_exceptions(
                exceptions=[
                    ValueError(f"Error message: {output}"),
                    exp,
                ]
            )

    Args:
        exceptions (list): List of exceptions to be raised. The 1st exception will appear in pytest error message;
                           all exceptions will appear in the stacktrace.

    """
    # After all exceptions were raised
    if not exceptions:
        return
    try:
        raise exceptions.pop()
    finally:
        raise_multiple_exceptions(exceptions=exceptions)


def get_node_pod(utility_pods, node):
    """
    This function will return a pod based on the node specified as an argument.

    Args:
        utility_pods (list): List of utility pods.
        node (Node or str): Node to get the pod for it.
    """
    _node_name = node.name if hasattr(node, "name") else node
    for pod in utility_pods:
        if pod.node.name == _node_name:
            return pod


class ExecCommandOnPod:
    def __init__(self, utility_pods, node):
        """
        Run command on pod with chroot /host

        Args:
            utility_pods (list): List of utility pods resources.
            node (Node): Node resource.

        Returns:
            str: Command output
        """
        self.pod = get_node_pod(utility_pods=utility_pods, node=node)
        if not self.pod:
            raise UtilityPodNotFoundError(node=node.name)

    def exec(self, command, chroot_host=True, ignore_rc=False, timeout=TIMEOUT_1MIN):
        chroot_command = "chroot /host" if chroot_host else ""
        _command = shlex.split(f"{chroot_command} bash -c {shlex.quote(command)}")
        return self.pod.execute(
            command=_command, ignore_rc=ignore_rc, timeout=timeout
        ).strip()

    def get_interface_ip(self, interface):
        out = self.exec(command=f"ip addr show {interface}")
        match_ip = re.search(r"[0-9]+(?:\.[0-9]+){3}", out)
        if match_ip:
            interface_ip = match_ip.group()
            if netaddr.valid_ipv4(interface_ip):
                return interface_ip

    @property
    def reboot(self):
        try:
            self.exec(command="sudo echo b > /proc/sysrq-trigger")
        except ApiException:
            return True
        return False

    @property
    def is_connective(self):
        return self.exec(command="ls")

    def interface_status(self, interface):
        return self.exec(command=f"cat /sys/class/net/{interface}/operstate")

    @property
    def release_info(self):
        out = self.exec(command="cat /etc/os-release")
        release_info = {}
        for line in out.strip().splitlines():
            values = line.split("=", 1)
            if len(values) != 2:
                continue
            release_info[values[0].strip()] = values[1].strip(" \"'")
        return release_info


def cluster_sanity(
    request,
    admin_client,
    cluster_storage_classes,
    nodes,
    hco_namespace,
    hco_status_conditions,
    expected_hco_status,
    junitxml_property=None,
):
    if "cluster_health_check" in request.config.getoption("-m"):
        LOGGER.warning("Skipping cluster sanity test, got -m cluster_health_check")
        return

    def _storage_sanity_check():
        sc_names = [sc.name for sc in cluster_storage_classes]
        config_sc = list([[*csc][0] for csc in py_config["storage_class_matrix"]])
        exists_sc = [scn for scn in config_sc if scn in sc_names]
        if sorted(config_sc) != sorted(exists_sc):
            raise ClusterSanityError(
                err_str=f"Cluster is missing storage class. Expected {config_sc}, On cluster {exists_sc}\n"
                f"either run with '--storage-class-matrix' or with '{skip_storage_classes_check}'"
            )

    skip_cluster_sanity_check = "--cluster-sanity-skip-check"
    skip_storage_classes_check = "--cluster-sanity-skip-storage-check"
    skip_nodes_check = "--cluster-sanity-skip-nodes-check"
    skip_hco_status_condition_check = "--cluster-sanity-skip-hco-check"
    exceptions_filename = "cluster_sanity_failure.txt"
    try:
        if request.session.config.getoption(skip_cluster_sanity_check):
            LOGGER.warning(
                f"Skipping cluster sanity check, got {skip_cluster_sanity_check}"
            )
            return
        LOGGER.info(
            f"Running cluster sanity. (To skip cluster sanity check pass {skip_cluster_sanity_check} to pytest)"
        )
        # Check storage class only if --cluster-sanity-skip-storage-check not passed to pytest.
        if request.session.config.getoption(skip_storage_classes_check):
            LOGGER.warning(
                f"Skipping storage classes check, got {skip_storage_classes_check}"
            )
        else:
            LOGGER.info(
                f"Check storage classes sanity. (To skip storage class sanity check pass {skip_storage_classes_check} "
                f"to pytest)"
            )
            _storage_sanity_check()

        # Check nodes only if --cluster-sanity-skip-nodes-check not passed to pytest.
        if request.session.config.getoption(skip_nodes_check):
            LOGGER.warning(f"Skipping nodes check, got {skip_nodes_check}")

        else:
            # validate that all the nodes are ready and schedulable and CNV pods are running
            LOGGER.info(
                f"Check nodes sanity. (To skip nodes sanity check pass {skip_nodes_check} to pytest)"
            )
            assert_nodes_ready(nodes=nodes)
            assert_nodes_schedulable(nodes=nodes)
            wait_for_pods_running(admin_client=admin_client, namespace=hco_namespace)

        # Check hco.status.conditions only if --cluster-sanity-skip-hco-check not passed to pytest.
        if request.session.config.getoption(skip_hco_status_condition_check):
            LOGGER.warning(
                f"Skipping HCO status conditions check, got {skip_hco_status_condition_check}"
            )
        else:
            # validate that hco.status.conditions indicates it is healthy
            validate_hco_status_conditions(
                hco_status_conditions=hco_status_conditions,
                expected_hco_status=expected_hco_status,
            )
    except (ClusterSanityError, NodeUnschedulableError, NodeNotReadyError) as ex:
        exit_pytest_execution(
            filename=exceptions_filename,
            message=ex.err_str,
            junitxml_property=junitxml_property,
        )


class ResourceMismatch(Exception):
    pass


def exit_pytest_execution(
    message, return_code=SANITY_TESTS_FAILURE, filename=None, junitxml_property=None
):
    """Exit pytest execution

    Exit pytest execution; invokes pytest_sessionfinish.
    Optionally, log an error message to tests-collected-info/utilities/pytest_exit_errors/<filename>

    Args:
        message (str):  Message to display upon exit and to log in errors file
        return_code (int. Default: 99): Exit return code
        filename (str, optional. Default: None): filename where the given message will be saved
        junitxml_property (pytest plugin): record_testsuite_property
    """
    if filename:
        base_directory = py_config["data_collector"]["data_collector_base_directory"]
        write_to_file(
            file_name=filename,
            content=message,
            extra_dir_name="pytest_exit_errors",
            base_directory=base_directory,
        )
    if junitxml_property:
        junitxml_property(name="exit_code", value=return_code)
    pytest.exit(msg=message, returncode=return_code)


def get_kubevirt_package_manifest(admin_client):
    return get_raw_package_manifest(
        admin_client=admin_client,
        name=py_config["hco_cr_name"],
        catalog_source=HCO_CATALOG_SOURCE,
    )


def get_raw_package_manifest(admin_client, name, catalog_source):
    """
    Gets PackageManifest ResourceField associated with catalog source.
    Multiple PackageManifest Resources exist with the same name but different labels.
    Requires raw=True

    Args:
        admin_client (DynamicClient): dynamic client object
        name (str): Name of PackageManifest
        catalog_source (str): Catalog source

    Returns:
        ResourceField or None: PackageManifest ResourceField or None if no matching resource found
    """
    for resource_field in PackageManifest.get(
        dyn_client=admin_client,
        namespace=py_config["marketplace_namespace"],
        field_selector=f"metadata.name={name}",
        label_selector=f"catalog={catalog_source}",
        raw=True,  # multiple packagemanifest exists with the same name but different labels
    ):
        LOGGER.info(
            f"Found expected packagemanefest: {resource_field.metadata.name}: "
            f"in catalog: {resource_field.metadata.labels.catalog}"
        )
        return resource_field
    LOGGER.warning(
        f"Not able to find any packagemanifest {name} in {catalog_source} source."
    )


def get_subscription(admin_client, namespace, subscription_name):
    """
    Gets subscription by name

    Args:
        admin_client (DynamicClient): Dynamic client object
        namespace (str): Name of the namespace
        subscription_name (str): Name of the subscription

    Returns:
        Resource: subscription resource

    Raises:
        NotFoundError: when a given subscription is not found in a given namespace
    """
    subscription = Subscription(
        client=admin_client,
        name=subscription_name,
        namespace=namespace,
    )
    if subscription.exists:
        return subscription
    raise ResourceNotFoundError(
        f"Subscription {subscription_name} not found in namespace: {namespace}"
    )


def get_csv_by_name(csv_name, admin_client, namespace):
    """
    Gets csv from a given namespace by name

    Args:
        csv_name (str): Name of the csv
        admin_client (DynamicClient): dynamic client object
        namespace (str): namespace name

    Returns:
        Resource: csv resource

    Raises:
        NotFoundError: when a given csv is not found in a given namespace
    """
    csv = utilities.infra.cluster_resource(ClusterServiceVersion)(
        client=admin_client, namespace=namespace, name=csv_name
    )
    if csv.exists:
        return csv
    raise ResourceNotFoundError(f"Csv {csv_name} not found in namespace: {namespace}")


def get_clusterversion(dyn_client):
    for cvo in ClusterVersion.get(dyn_client=dyn_client):
        return cvo


def get_deployments(admin_client, namespace):
    return list(Deployment.get(dyn_client=admin_client, namespace=namespace))


def cnv_target_images(target_related_images_name_and_versions):
    return [item["image"] for item in target_related_images_name_and_versions.values()]


def get_related_images_name_and_version(dyn_client, hco_namespace, version):
    related_images_name_and_versions = {}
    csv = get_csv_by_name(
        admin_client=dyn_client,
        namespace=hco_namespace,
        csv_name=version,
    )
    for item in csv.instance.spec.relatedImages:
        # Example: 'registry.redhat.io/container-native-virtualization/node-maintenance-operator:v2.6.3-1'
        image_name_version = re.search(
            r".*/(?P<name>.*?):(?P<version>.*)", item["name"]
        ).groupdict()
        image_name = image_name_version["name"]
        related_images_name_and_versions[image_name] = {
            "image": item["image"],
            "version": image_name_version["version"],
            "is_operator_image": image_name.endswith(OPERATOR_NAME_SUFFIX),
        }
    return related_images_name_and_versions


def is_bug_open(bug_id):
    bug = get_bug(bug_id=bug_id)
    bug_status = bug.status
    status_for_logger = f"Bug {bug_id}: {bug.summary} status is {bug_status}"
    if bug_status not in BUG_STATUS_CLOSED:
        LOGGER.info(status_for_logger)
        return True

    LOGGER.warning(f"{status_for_logger} bug should be removed from the codebase")
    return False


def run_virtctl_command(command, namespace=None):
    """
    Run virtctl command

    Args:
        command (list): Command to run
        namespace (str, default:None): Namespace to send to virtctl command

    Returns:
        tuple: True, out if command succeeded, False, err otherwise.
    """
    virtctl_cmd = ["virtctl"]
    kubeconfig = os.getenv("KUBECONFIG")
    if namespace:
        virtctl_cmd.extend(["-n", namespace])

    if kubeconfig:
        virtctl_cmd.extend(["--kubeconfig", kubeconfig])

    virtctl_cmd.extend(command)
    res, out, err = run_command(command=virtctl_cmd)

    return res, out, err


def validate_hco_status_conditions(hco_status_conditions, expected_hco_status):
    current_status = {
        condition["type"]: condition["status"] for condition in hco_status_conditions
    }
    mismatch_statuses = []

    for condition_type, condition_status in expected_hco_status.items():
        if current_status[condition_type] != condition_status:
            mismatch_statuses.append(
                f"Current condition type {condition_type} does not match expected status {condition_status}"
            )

    if mismatch_statuses:
        mismatch_str = "\n".join(mismatch_statuses)
        raise ClusterSanityError(
            err_str=f"{mismatch_str} \nHCO is unhealthy. "
            f"Expected {expected_hco_status}, Current: {hco_status_conditions}"
        )


def is_jira_open(jira_id):
    return get_jira_status(jira=jira_id) not in JIRA_STATUS_CLOSED


def get_hyperconverged_resource(client, hco_ns_name):
    hco_name = py_config["hco_cr_name"]
    hco = HyperConverged(
        client=client,
        namespace=hco_ns_name,
        name=hco_name,
    )
    if hco.exists:
        return hco
    raise ResourceNotFoundError(
        f"Hyperconverged: {hco_name} not found in {hco_ns_name}"
    )


def get_utility_pods_from_nodes(nodes, admin_client, label_selector):
    pods = list(Pod.get(admin_client, label_selector=label_selector))
    nodes_without_utility_pods = [
        node.name for node in nodes if node.name not in [pod.node.name for pod in pods]
    ]
    assert (
        not nodes_without_utility_pods
    ), f"Missing pods with label {label_selector} for: {' '.join(nodes_without_utility_pods)}"
    return [pod for pod in pods if pod.node.name in [node.name for node in nodes]]


def label_nodes(nodes, labels):
    updates = [
        ResourceEditor({node: {"metadata": {"labels": labels}}}) for node in nodes
    ]

    for update in updates:
        update.update(backup_resources=True)
    yield nodes
    for update in updates:
        update.restore()


def get_daemonsets(admin_client, namespace):
    return list(DaemonSet.get(dyn_client=admin_client, namespace=namespace))


@contextmanager
def scale_deployment_replicas(deployment_name, namespace, replica_count):
    """
    It scales deployments replicas. At the end of the test restores them back
    """
    deployment = Deployment(name=deployment_name, namespace=namespace)
    initial_replicas = deployment.instance.spec.replicas
    deployment.scale_replicas(replica_count=replica_count)
    deployment.wait_for_replicas(deployed=replica_count > 0)
    yield
    deployment.scale_replicas(replica_count=initial_replicas)
    deployment.wait_for_replicas(deployed=initial_replicas > 0)


def get_kube_system_namespace():
    ns = Namespace(name="kube-system")
    if ns.exists:
        return ns
    raise ResourceNotFoundError(f"{ns.name} namespace not found")


def get_console_spec_links(admin_client, name):
    console_cli_download_resource_content = ConsoleCLIDownload(
        name=name, client=admin_client
    )
    if console_cli_download_resource_content.exists:
        return console_cli_download_resource_content.instance.spec.links

    raise ResourceNotFoundError(f"{name} ConsoleCLIDownload not found")


def get_all_console_links(console_cli_downloads_spec_links):
    all_urls = [entry["href"] for entry in console_cli_downloads_spec_links]
    assert all_urls, (
        "No URL entries found in the resource: "
        f"console_cli_download_resource_content={console_cli_downloads_spec_links}"
    )
    return all_urls


def download_and_extract_file_from_cluster(tmpdir, url):
    """
    Download and extract archive file from the cluster

    Args:
        tmpdir (py.path.local): temporary folder to download the files.
        url (str): URL to download from.

    Returns:
        list: list of extracted filenames
    """
    zip_file_extension = ".zip"
    LOGGER.info(f"Downloading archive: url={url}")
    urllib3.disable_warnings()  # TODO: remove this when we fix the SSL warning
    response = requests.get(url, verify=False)
    assert (
        response.status_code == http.HTTPStatus.OK
    ), f"Response status code: {response.status_code}"
    archive_file_data = io.BytesIO(initial_bytes=response.content)
    LOGGER.info("Extract the archive")
    if url.endswith(zip_file_extension):
        archive_file_object = zipfile.ZipFile(file=archive_file_data)
    else:
        archive_file_object = tarfile.open(fileobj=archive_file_data, mode="r")
    archive_file_object.extractall(path=tmpdir)
    extracted_filenames = (
        archive_file_object.namelist()
        if url.endswith(zip_file_extension)
        else archive_file_object.getnames()
    )
    return [os.path.join(tmpdir.strpath, namelist) for namelist in extracted_filenames]


def get_and_extract_file_from_cluster(urls, system_os, dest_dir):
    for url in urls:
        if system_os in url:
            extracted_files = download_and_extract_file_from_cluster(
                tmpdir=dest_dir, url=url
            )
            assert (
                len(extracted_files) == 1
            ), f"Only a single file expected in archive: extracted_files={extracted_files}"
            return extracted_files[0]

    raise UrlNotFoundError(f"Url not found for system_os={system_os}")


def download_file_from_cluster(get_console_spec_links_name, dest_dir):
    console_cli_links = get_console_spec_links(
        admin_client=get_admin_client(),
        name=get_console_spec_links_name,
    )
    download_urls = get_all_console_links(
        console_cli_downloads_spec_links=console_cli_links
    )
    binary_file = get_and_extract_file_from_cluster(
        system_os=platform.system().lower(),
        urls=download_urls,
        dest_dir=dest_dir,
    )
    os.chmod(binary_file, stat.S_IRUSR | stat.S_IXUSR)


def get_nodes_with_label(nodes, label):
    return [node for node in nodes if label in node.labels.keys()]


def get_daemonset_yaml_file_with_image_hash(
    is_upstream_distribution, generated_pulled_secret=None, service_account=None
):
    ds_yaml_file = os.path.abspath(
        f"utilities/manifests/utility-daemonset"
        f"{'_upstream' if is_upstream_distribution else ''}.yaml"
    )

    image_info = utilities.virt.get_oc_image_info(
        image="quay.io/openshift-cnv/qe-cnv-tests-net-util-container",
        pull_secret=generated_pulled_secret,
    )
    with open(ds_yaml_file, "r") as fd:
        ds_yaml = yaml.safe_load(fd.read())

    template_spec = ds_yaml["spec"]["template"]["spec"]
    container = template_spec["containers"][0]
    container["image"] = f"{container['image']}@{image_info['digest']}"
    template_spec["containers"][0] = container
    if service_account:
        template_spec["serviceAccount"] = service_account.name
        template_spec["serviceAccountName"] = service_account.name
    return io.StringIO(yaml.dump(ds_yaml))


def unique_name(name, service_type=None):
    # Sets unique name
    service_type = f"{service_type}-" if service_type else ""
    return f"{name}-{service_type}{time.time()}".replace(".", "-")


def get_http_image_url(image_directory, image_name):
    return f"{get_images_server_url(schema='http')}{image_directory}/{image_name}"


def get_openshift_pull_secret(client=None):
    pull_secret_name = "pull-secret"
    secret = Secret(
        client=client or get_admin_client(),
        name=pull_secret_name,
        namespace=OPENSHIFT_CONFIG_NAMESPACE,
    )
    assert (
        secret.exists
    ), f"Pull-secret {pull_secret_name} not found in namespace {OPENSHIFT_CONFIG_NAMESPACE}"
    return secret


def generate_openshift_pull_secret_file(client=None):
    pull_secret = get_openshift_pull_secret(client=client)
    pull_secret_path = tempfile.mkdtemp(suffix="-cnv-tests-pull-secret")
    json_file = os.path.join(pull_secret_path, "pull-secrets.json")
    secret = base64.b64decode(pull_secret.instance.data[".dockerconfigjson"]).decode(
        encoding="utf-8"
    )
    with open(file=json_file, mode="w") as outfile:
        outfile.write(secret)
    return json_file


def get_node_audit_log_entries(log, node, log_entry):
    return subprocess.getoutput(
        f"{OC_ADM_LOGS_COMMAND} {node} {AUDIT_LOGS_PATH}/{log} | grep {shlex.quote(log_entry)}"
    ).splitlines()


def get_node_audit_log_line_dict(logs, node, log_entry):
    for log in logs:
        deprecated_api_lines = get_node_audit_log_entries(
            log=log, node=node, log_entry=log_entry
        )
        if deprecated_api_lines:
            for line in deprecated_api_lines:
                try:
                    yield json.loads(line)
                except json.decoder.JSONDecodeError:
                    LOGGER.error(f"Unable to parse line: {line!r}")
                    raise


def wait_for_node_status(node, status=True, wait_timeout=TIMEOUT_1MIN):
    """Wait for node status Ready (status=True) or NotReady (status=False)"""
    for sample in TimeoutSampler(
        wait_timeout=wait_timeout, sleep=1, func=lambda: node.kubelet_ready
    ):
        if (status and sample) or (not status and not sample):
            return
