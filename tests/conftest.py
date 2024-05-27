# -*- coding: utf-8 -*-

"""
Pytest conftest file for CNV tests
"""
import copy
import ipaddress
import logging
import os
import os.path
import re
import shutil
import subprocess
import tempfile
from collections import defaultdict
from signal import SIGINT, SIGTERM, getsignal, signal
from subprocess import PIPE, CalledProcessError, Popen, check_output

import bcrypt
import kubernetes
import packaging.version
import paramiko
import pytest
from ocp_resources.catalog_source import CatalogSource
from ocp_resources.cdi import CDI
from ocp_resources.cdi_config import CDIConfig
from ocp_resources.cluster_role import ClusterRole
from ocp_resources.cluster_service_version import ClusterServiceVersion
from ocp_resources.configmap import ConfigMap
from ocp_resources.custom_resource_definition import CustomResourceDefinition
from ocp_resources.daemonset import DaemonSet
from ocp_resources.datavolume import DataVolume
from ocp_resources.hostpath_provisioner import HostPathProvisioner
from ocp_resources.infrastructure import Infrastructure
from ocp_resources.installplan import InstallPlan
from ocp_resources.mutating_webhook_config import MutatingWebhookConfiguration
from ocp_resources.namespace import Namespace
from ocp_resources.network import Network
from ocp_resources.network_addons_config import NetworkAddonsConfig
from ocp_resources.node import Node
from ocp_resources.node_network_state import NodeNetworkState
from ocp_resources.oauth import OAuth
from ocp_resources.persistent_volume_claim import PersistentVolumeClaim
from ocp_resources.pod import Pod
from ocp_resources.resource import Resource, ResourceEditor
from ocp_resources.role_binding import RoleBinding
from ocp_resources.secret import Secret
from ocp_resources.service_account import ServiceAccount
from ocp_resources.sriov_network_node_state import SriovNetworkNodeState
from ocp_resources.storage_class import StorageClass
from ocp_resources.template import Template
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from ocp_utilities.infra import get_client
from openshift.dynamic import DynamicClient
from openshift.dynamic.exceptions import NotFoundError, ResourceNotFoundError
from packaging.version import Version
from pyhelper_utils.shell import run_command
from pytest_testconfig import config as py_config

import utilities.hco
from tests.utils import (
    VirtualMachineInstanceTypeForTest,
    VirtualMachinePreferenceForTest,
    get_hco_version_name,
)
from utilities.constants import (
    AMD,
    AUDIT_LOGS_PATH,
    CDI_KUBEVIRT_HYPERCONVERGED,
    CNV_TEST_SERVICE_ACCOUNT,
    CNV_VM_SSH_KEY_PATH,
    CPU_MODEL_LABEL_PREFIX,
    DEFAULT_HCO_CONDITIONS,
    EUS_ERROR_CODE,
    HCO_SUBSCRIPTION,
    HOSTPATH_CSI_BASIC,
    HOTFIX_STR,
    ICSP_FILTER_BY_OS_LINUX_AMD64,
    INTEL,
    KMP_ENABLED_LABEL,
    KMP_VM_ASSIGNMENT_LABEL,
    KUBECONFIG,
    KUBEMACPOOL_MAC_RANGE_CONFIG,
    LINUX_BRIDGE,
    MASTER_NODE_LABEL_KEY,
    NODE_TYPE_WORKER_LABEL,
    OC_ADM_LOGS_COMMAND,
    OVS_BRIDGE,
    POD_SECURITY_NAMESPACE_LABELS,
    TIMEOUT_4MIN,
    TIMEOUT_5MIN,
    TIMEOUT_6MIN,
    UNPRIVILEGED_PASSWORD,
    UNPRIVILEGED_USER,
    UTILITY,
    VIRT_OPERATOR,
    VIRTCTL_CLI_DOWNLOADS,
    WORKER_NODE_LABEL_KEY,
    WORKERS_TYPE,
    Images,
    NamespacesNames,
    StorageClassNames,
    UpgradeStreams,
)
from utilities.exceptions import CommonNodesCpusNotFoundError
from utilities.infra import (
    ClusterHosts,
    ExecCommandOnPod,
    add_scc_to_service_account,
    base64_encode_str,
    cluster_resource,
    cluster_sanity,
    create_ns,
    download_file_from_cluster,
    exit_pytest_execution,
    generate_namespace_name,
    generate_openshift_pull_secret_file,
    get_clusterversion,
    get_csv_by_name,
    get_daemonset_yaml_file_with_image_hash,
    get_deployment_by_name,
    get_http_image_url,
    get_hyperconverged_resource,
    get_nodes_with_label,
    get_pods,
    get_schedulable_nodes_ips,
    get_subscription,
    get_utility_pods_from_nodes,
    label_nodes,
    name_prefix,
    run_virtctl_command,
    scale_deployment_replicas,
    wait_for_pods_deletion,
)
from utilities.network import (
    EthernetNetworkConfigurationPolicy,
    MacPool,
    SriovIfaceNotFound,
    cloud_init,
    create_sriov_node_policy,
    enable_hyperconverged_ovs_annotations,
    get_cluster_cni_type,
    network_device,
    network_nad,
    wait_for_ovs_daemonset_resource,
    wait_for_ovs_status,
)
from utilities.operator import disable_default_sources_in_operatorhub
from utilities.ssp import get_data_import_crons, get_ssp_resource
from utilities.storage import (
    create_or_update_data_source,
    data_volume,
    default_storage_class,
    get_images_server_url,
    is_snapshot_supported_by_sc,
    sc_is_hpp_with_immediate_volume_binding,
)
from utilities.virt import (
    Prometheus,
    VirtualMachineForTests,
    fedora_vm_body,
    get_all_virt_pods_with_running_status,
    get_base_templates_list,
    get_hyperconverged_kubevirt,
    get_hyperconverged_ovs_annotations,
    get_kubevirt_hyperconverged_spec,
    kubernetes_taint_exists,
    running_vm,
    vm_instance_from_template,
    wait_for_windows_vm,
)


LOGGER = logging.getLogger(__name__)
HTTP_SECRET_NAME = "htpass-secret-for-cnv-tests"
HTPASSWD_PROVIDER_DICT = {
    "name": "htpasswd_provider",
    "mappingMethod": "claim",
    "type": "HTPasswd",
    "htpasswd": {"fileData": {"name": HTTP_SECRET_NAME}},
}
ACCESS_TOKEN = {
    "accessTokenMaxAgeSeconds": 604800,
    "accessTokenInactivityTimeout": None,
}
CNV_NOT_INSTALLED = "CNV not yet installed."

AMD_CPU_MODELS = ["Opteron_G1", "Opteron_G2"]

NIGHTLY_ART_IMAGE = (
    "quay.io/openshift-release-dev/ocp-release-nightly:iib-int-index-art-operators"
)


def login_to_account(api_address, user, password=None):
    """
    Helper function for login. Raise exception if login failed
    """
    stop_errors = [
        "connect: no route to host",
        "x509: certificate signed by unknown authority",
    ]
    login_command = f"oc login {api_address} -u {user}"
    if password:
        login_command += f" -p {password}"

    samples = TimeoutSampler(
        wait_timeout=60,
        sleep=3,
        exceptions_dict={CalledProcessError: []},
        func=Popen,
        args=login_command,
        shell=True,
        stdout=PIPE,
        stderr=PIPE,
    )
    login_result = None
    try:
        LOGGER.info(
            f"Trying to login to {user} user shell. Login command: {login_command}"
        )
        for sample in samples:
            login_result = sample.communicate()
            if sample.returncode == 0:
                LOGGER.info(f"Login to {user} user shell - success")
                return True

            if [err for err in stop_errors if err in login_result[1].decode("utf-8")]:
                break

    except TimeoutExpiredError:
        if login_result:
            LOGGER.warning(
                f"Login to unprivileged user - failed due to the following error: "
                f"{login_result[0].decode('utf-8')} {login_result[1].decode('utf-8')}"
            )
        return False


@pytest.fixture(scope="session")
def junitxml_polarion(record_testsuite_property):
    """
    Add polarion needed attributes to junit xml

    export as os environment:
    POLARION_CUSTOM_PLANNEDIN
    POLARION_TESTRUN_ID
    POLARION_TIER
    """
    record_testsuite_property("polarion-custom-isautomated", "True")
    record_testsuite_property("polarion-testrun-status-id", "inprogress")
    record_testsuite_property(
        "polarion-custom-plannedin", os.getenv("POLARION_CUSTOM_PLANNEDIN")
    )
    record_testsuite_property("polarion-user-id", "cnvqe")
    record_testsuite_property("polarion-project-id", "CNV")
    record_testsuite_property("polarion-response-myproduct", "cnv-test-run")
    record_testsuite_property("polarion-testrun-id", os.getenv("POLARION_TESTRUN_ID"))
    record_testsuite_property("polarion-custom-env_tier", os.getenv("POLARION_TIER"))
    record_testsuite_property("polarion-custom-env_os", os.getenv("POLARION_OS"))


@pytest.fixture(scope="session")
def kubeconfig_export_path():
    return os.environ.get(KUBECONFIG)


@pytest.fixture(scope="session")
def exported_kubeconfig(unprivileged_secret, kubeconfig_export_path):
    if not unprivileged_secret:
        yield
    else:
        kubeconfig_path = tempfile.mkdtemp(suffix="-cnv-tests-kubeconfig")
        LOGGER.info(f"Kubeconfig for this run is: {kubeconfig_path}")
        if not os.path.isdir(kubeconfig_path):
            os.mkdir(kubeconfig_path)

        dest_path = os.path.join(kubeconfig_path, KUBECONFIG.lower())

        LOGGER.info(f"Copy {KUBECONFIG} to {dest_path}")
        shutil.copyfile(src=kubeconfig_export_path, dst=dest_path)
        LOGGER.info(f"Set: {KUBECONFIG}={dest_path.lower()}")
        os.environ[KUBECONFIG] = dest_path
        yield
        LOGGER.info(f"Set: {KUBECONFIG}={kubeconfig_export_path.lower()}")
        os.environ[KUBECONFIG] = kubeconfig_export_path


@pytest.fixture(scope="session")
def admin_client():
    """
    Get DynamicClient
    """
    return get_client()


@pytest.fixture(scope="session")
def unprivileged_secret(admin_client, skip_unprivileged_client):
    if skip_unprivileged_client:
        yield

    else:
        password = UNPRIVILEGED_PASSWORD.encode()
        enc_password = bcrypt.hashpw(password, bcrypt.gensalt(5, prefix=b"2a")).decode()
        crypto_credentials = f"{UNPRIVILEGED_USER}:{enc_password}"
        with cluster_resource(Secret)(
            name=HTTP_SECRET_NAME,
            namespace=NamespacesNames.OPENSHIFT_CONFIG,
            htpasswd=base64_encode_str(text=crypto_credentials),
        ) as secret:
            yield secret

        #  Wait for oauth-openshift deployment to update after removing htpass-secret
        _wait_for_oauth_openshift_deployment()


def _wait_for_oauth_openshift_deployment():
    dp = get_deployment_by_name(
        deployment_name="oauth-openshift",
        namespace_name="openshift-authentication",
    )

    _log = f"Wait for {dp.name} -> Type: Progressing -> Reason:"

    def _wait_sampler(_reason):
        sampler = TimeoutSampler(
            wait_timeout=TIMEOUT_4MIN,
            sleep=1,
            func=lambda: dp.instance.status.conditions,
        )
        for sample in sampler:
            for _spl in sample:
                if _spl.type == "Progressing" and _spl.reason == _reason:
                    return

    for reason in ("ReplicaSetUpdated", "NewReplicaSetAvailable"):
        LOGGER.info(f"{_log} {reason}")
        _wait_sampler(_reason=reason)


@pytest.fixture(scope="session")
def skip_unprivileged_client(is_upstream_distribution):
    # To disable unprivileged_client pass --tc=no_unprivileged_client:True to pytest commandline.
    return is_upstream_distribution or py_config.get("no_unprivileged_client")


@pytest.fixture(scope="session")
def identity_provider_config(skip_unprivileged_client, admin_client):
    if skip_unprivileged_client:
        return

    return OAuth(client=admin_client, name="cluster")


@pytest.fixture(scope="session")
def unprivileged_client(
    skip_unprivileged_client,
    admin_client,
    unprivileged_secret,
    identity_provider_config,
    exported_kubeconfig,
):
    """
    Provides none privilege API client
    """
    # TODO: Reduce cognitive complexity
    if skip_unprivileged_client:
        yield

    else:
        token = None
        kube_config_path = os.path.join(os.path.expanduser("~"), ".kube/config")
        kubeconfig_env = os.environ.get(KUBECONFIG)
        kube_config_exists = os.path.isfile(kube_config_path)
        if kubeconfig_env and kube_config_exists:
            raise ValueError(
                f"Both {KUBECONFIG} {kubeconfig_env} and {kube_config_path} exists. "
                f"Only one should be used, "
                f"either remove {kube_config_path} file or unset {KUBECONFIG}"
            )
        # Update identity provider
        identity_provider_config_editor = ResourceEditor(
            patches={
                identity_provider_config: {
                    "metadata": {"name": identity_provider_config.name},
                    "spec": {
                        "identityProviders": [HTPASSWD_PROVIDER_DICT],
                        "tokenConfig": ACCESS_TOKEN,
                    },
                }
            }
        )
        identity_provider_config_editor.update(backup_resources=True)
        _wait_for_oauth_openshift_deployment()
        current_user = (
            check_output("oc whoami", shell=True).decode().strip()
        )  # Get current admin account
        if kube_config_exists:
            os.environ[KUBECONFIG] = ""

        if login_to_account(
            api_address=admin_client.configuration.host,
            user=UNPRIVILEGED_USER,
            password=UNPRIVILEGED_PASSWORD,
        ):  # Login to unprivileged account
            token = (
                check_output("oc whoami -t", shell=True).decode().strip()
            )  # Get token
            token_auth = {
                "api_key": {"authorization": f"Bearer {token}"},
                "host": admin_client.configuration.host,
                "verify_ssl": True,
                "ssl_ca_cert": admin_client.configuration.ssl_ca_cert,
            }
            configuration = kubernetes.client.Configuration()
            for k, v in token_auth.items():
                setattr(configuration, k, v)

            if kubeconfig_env:
                os.environ[KUBECONFIG] = kubeconfig_env

            login_to_account(
                api_address=admin_client.configuration.host,
                user=current_user.strip(),
            )  # Get back to admin account

            k8s_client = kubernetes.client.ApiClient(configuration)
            yield DynamicClient(k8s_client)
        else:
            yield

        # Teardown
        if identity_provider_config_editor:
            identity_provider_config_editor.restore()

        if token:
            try:
                if kube_config_exists:
                    os.environ[KUBECONFIG] = ""

                login_to_account(
                    api_address=admin_client.configuration.host,
                    user=UNPRIVILEGED_USER,
                    password=UNPRIVILEGED_PASSWORD,
                )  # Login to unprivileged account
                LOGGER.info("Logout unprivileged_client")
                Popen(args=["oc", "logout"], stdout=PIPE, stderr=PIPE).communicate()
            finally:
                if kubeconfig_env:
                    os.environ[KUBECONFIG] = kubeconfig_env

                login_to_account(
                    api_address=admin_client.configuration.host,
                    user=current_user.strip(),
                )  # Get back to admin account


@pytest.fixture(scope="session")
def schedulable_node_ips(schedulable_nodes):
    """
    Store all kubevirt.io/schedulable=true IPs
    """
    return get_schedulable_nodes_ips(nodes=schedulable_nodes)


@pytest.fixture(scope="session")
def skip_when_one_node(schedulable_nodes):
    if len(schedulable_nodes) < 2:
        pytest.skip("Test requires at least 2 nodes")


@pytest.fixture(scope="session")
def nodes(admin_client):
    yield list(Node.get(dyn_client=admin_client))


@pytest.fixture(scope="session")
def schedulable_nodes(nodes):
    """Get nodes marked as schedulable by kubevirt"""
    schedulable_label = "kubevirt.io/schedulable"
    yield [
        node
        for node in nodes
        if schedulable_label in node.labels.keys()
        and node.labels[schedulable_label] == "true"
        and not node.instance.spec.unschedulable
        and not kubernetes_taint_exists(node)
        and node.kubelet_ready
    ]


@pytest.fixture(scope="session")
def workers(nodes):
    return get_nodes_with_label(nodes=nodes, label=WORKER_NODE_LABEL_KEY)


@pytest.fixture(scope="session")
def masters(nodes):
    return get_nodes_with_label(nodes=nodes, label=MASTER_NODE_LABEL_KEY)


@pytest.fixture(scope="session")
def cnv_tests_utilities_namespace(admin_client, installing_cnv):
    if installing_cnv:
        yield
    else:
        yield from create_ns(
            admin_client=admin_client,
            labels=POD_SECURITY_NAMESPACE_LABELS,
            name="cnv-tests-utilities",
        )


@pytest.fixture(scope="session")
def cnv_tests_utilities_service_account(cnv_tests_utilities_namespace, installing_cnv):
    if installing_cnv:
        yield
    else:
        with cluster_resource(ServiceAccount)(
            name=CNV_TEST_SERVICE_ACCOUNT,
            namespace=cnv_tests_utilities_namespace.name,
        ) as service_account:
            add_scc_to_service_account(
                namespace=cnv_tests_utilities_namespace.name,
                scc_name="privileged",
                sa_name=service_account.name,
            )
            yield service_account


@pytest.fixture(scope="session")
def utility_daemonset(
    admin_client,
    installing_cnv,
    is_upstream_distribution,
    generated_pulled_secret,
    cnv_tests_utilities_namespace,
    cnv_tests_utilities_service_account,
):
    """
    Deploy utility daemonset into the kube-system namespace.

    This daemonset deploys a pod on every node with hostNetwork and the main usage is to run commands on the hosts.
    For example to create linux bridge and other components related to the host configuration.
    """
    if installing_cnv:
        yield
    else:
        modified_ds_yaml_file = get_daemonset_yaml_file_with_image_hash(
            is_upstream_distribution=is_upstream_distribution,
            generated_pulled_secret=generated_pulled_secret,
            service_account=cnv_tests_utilities_service_account,
        )
        with cluster_resource(DaemonSet)(yaml_file=modified_ds_yaml_file) as ds:
            ds.wait_until_deployed()
            yield ds


@pytest.fixture(scope="session")
def pull_secret_directory(tmpdir_factory):
    yield tmpdir_factory.mktemp("pullsecret-folder")


@pytest.fixture(scope="session")
def generated_pulled_secret(
    is_downstream_distribution,
    is_production_source,
    installing_cnv,
    admin_client,
):
    if is_downstream_distribution:
        if is_production_source and installing_cnv:
            return
        return generate_openshift_pull_secret_file()


@pytest.fixture(scope="session")
def workers_utility_pods(admin_client, workers, utility_daemonset, installing_cnv):
    """
    Get utility pods from worker nodes.
    When the tests start we deploy a pod on every worker node in the cluster using a daemonset.
    These pods have a label of cnv-test=utility and they are privileged pods with hostnetwork=true
    """
    if installing_cnv:
        return
    return get_utility_pods_from_nodes(
        nodes=workers,
        admin_client=admin_client,
        label_selector="cnv-test=utility",
    )


@pytest.fixture(scope="session")
def masters_utility_pods(admin_client, installing_cnv, masters, utility_daemonset):
    """
    Get utility pods from master nodes.
    When the tests start we deploy a pod on every master node in the cluster using a daemonset.
    These pods have a label of cnv-test=utility and they are privileged pods with hostnetwork=true
    """
    if installing_cnv:
        return
    return get_utility_pods_from_nodes(
        nodes=masters,
        admin_client=admin_client,
        label_selector="cnv-test=utility",
    )


@pytest.fixture(scope="session")
def node_physical_nics(admin_client, workers_utility_pods):
    interfaces = {}
    for pod in workers_utility_pods:
        node = pod.instance.spec.nodeName
        output = pod.execute(
            ["bash", "-c", "ls -la /sys/class/net | grep pci | grep -o '[^/]*$'"]
        ).split("\n")
        interfaces[node] = list(filter(None, output))  # Filter out empty lines

    LOGGER.info(f"Nodes physical NICs: {interfaces}")
    return interfaces


@pytest.fixture(scope="session")
def ovn_kubernetes_cluster(admin_client):
    return get_cluster_cni_type(admin_client=admin_client) == "OVNKubernetes"


@pytest.fixture(scope="session")
def skip_if_ovn_cluster(ovn_kubernetes_cluster):
    if ovn_kubernetes_cluster:
        pytest.skip("Test cannot run on cluster with OVN network type")


@pytest.fixture(scope="session")
def nodes_active_nics(
    workers,
    workers_utility_pods,
    node_physical_nics,
):
    # TODO: Reduce cognitive complexity
    def _bridge_ports(node_interface):
        ports = set()
        if node_interface["type"] in (OVS_BRIDGE, LINUX_BRIDGE) and node_interface[
            "bridge"
        ].get("port"):
            for bridge_port in node_interface["bridge"]["port"]:
                ports.add(bridge_port["name"])
        return ports

    """
    Get nodes active NICs.
    First NIC is management NIC
    """
    nodes_nics = {}
    for node in workers:
        nodes_nics[node.name] = {"available": [], "occupied": []}
        nns = NodeNetworkState(name=node.name)

        for node_iface in nns.interfaces:
            iface_name = node_iface["name"]
            #  Exclude SR-IOV (VFs) interfaces.
            if re.findall(r"v\d+$", iface_name):
                continue

            # If the interface is a bridge with physical ports, then these ports should be labeled as occupied.
            for bridge_port in _bridge_ports(node_interface=node_iface):
                if (
                    bridge_port in node_physical_nics[node.name]
                    and bridge_port not in nodes_nics[node.name]["occupied"]
                ):
                    LOGGER.warning(
                        f"{node.name}:{bridge_port} is a port of {iface_name} bridge - adding it to the node's "
                        "occupied interfaces list."
                    )
                    nodes_nics[node.name]["occupied"].append(bridge_port)
                    if bridge_port in nodes_nics[node.name]["available"]:
                        nodes_nics[node.name]["available"].remove(bridge_port)

            if iface_name in nodes_nics[node.name]["occupied"]:
                continue

            # BZ 1885605 <skip-bug-check> workaround: If any of the node's physical interfaces serves as a port of an
            # OVS bridge, it shouldn't be used for tests' node networking.
            bridge_ports = _bridge_ports(node_interface=node_iface)
            for port in bridge_ports:
                if port in node_physical_nics[node.name]:
                    nodes_nics[node.name]["occupied"].append(port)
                    if port in nodes_nics[node.name]["available"]:
                        nodes_nics[node.name]["available"].remove(port)

            if iface_name not in node_physical_nics[node.name]:
                continue

            physically_connected = (
                ExecCommandOnPod(utility_pods=workers_utility_pods, node=node)
                .exec(
                    command=f"nmcli -g WIRED-PROPERTIES.CARRIER device show {iface_name}"
                )
                .lower()
            )
            if physically_connected != "on":
                LOGGER.warning(f"{node.name} {iface_name} link is down")
                continue

            if node_iface["ipv4"].get("address"):
                nodes_nics[node.name]["occupied"].append(iface_name)
            else:
                nodes_nics[node.name]["available"].append(iface_name)

    LOGGER.info(f"Nodes active NICs: {nodes_nics}")
    return nodes_nics


@pytest.fixture(scope="session")
def nodes_available_nics(nodes_active_nics):
    return {
        node: nodes_active_nics[node]["available"] for node in nodes_active_nics.keys()
    }


@pytest.fixture(scope="session")
def nodes_occupied_nics(nodes_active_nics):
    return {
        node: nodes_active_nics[node]["occupied"] for node in nodes_active_nics.keys()
    }


@pytest.fixture(scope="session")
def multi_nics_nodes(hosts_common_available_ports):
    """
    Check if nodes has any available NICs
    """
    return len(hosts_common_available_ports) > 1


@pytest.fixture(scope="session")
def skip_if_no_multinic_nodes(multi_nics_nodes):
    if not multi_nics_nodes:
        pytest.skip("Only run on multi NICs node")


@pytest.fixture(scope="module")
def namespace(request, admin_client, unprivileged_client):
    """
    To create namespace using admin client, pass {"use_unprivileged_client": False} to request.param
    (default for "use_unprivileged_client" is True)
    """
    use_unprivileged_client = getattr(request, "param", {}).get(
        "use_unprivileged_client", True
    )
    teardown = getattr(request, "param", {}).get("teardown", True)
    unprivileged_client = unprivileged_client if use_unprivileged_client else None
    yield from create_ns(
        unprivileged_client=unprivileged_client,
        admin_client=admin_client,
        name=generate_namespace_name(
            file_path=request.fspath.strpath.split(f"{os.path.dirname(__file__)}/")[1]
        ),
        teardown=teardown,
        delete_timeout=TIMEOUT_6MIN,
    )


@pytest.fixture(scope="session")
def skip_upstream(is_upstream_distribution):
    if is_upstream_distribution:
        pytest.skip(
            msg="Running only on downstream,"
            "Reason: HTTP/Registry servers are not available for upstream",
        )


@pytest.fixture(scope="session")
def leftovers_cleanup(
    admin_client, cnv_tests_utilities_namespace, identity_provider_config
):
    LOGGER.info("Checking for leftover resources")
    secret = Secret(
        client=admin_client,
        name=HTTP_SECRET_NAME,
        namespace=NamespacesNames.OPENSHIFT_CONFIG,
    )
    ds = None
    if cnv_tests_utilities_namespace:
        ds = DaemonSet(
            client=admin_client,
            name=UTILITY,
            namespace=cnv_tests_utilities_namespace.name,
        )
    #  Delete Secret and DaemonSet created by us.
    for resource_ in (secret, ds):
        if resource_ and resource_.exists:
            resource_.delete(wait=True)

    #  Remove leftovers from OAuth
    if not identity_provider_config:
        # When running CI (k8s) OAuth is not exists on the cluster.
        LOGGER.warning("OAuth does not exist on the cluster")
        return

    identity_providers_spec = identity_provider_config.instance.to_dict()["spec"]
    identity_providers_token = identity_providers_spec.get("tokenConfig")
    identity_providers = identity_providers_spec.get("identityProviders", [])

    if ACCESS_TOKEN == identity_providers_token:
        identity_providers_spec["tokenConfig"] = None

    if HTPASSWD_PROVIDER_DICT in identity_providers:
        identity_providers.pop(identity_providers.index(HTPASSWD_PROVIDER_DICT))
        identity_providers_spec["identityProviders"] = identity_providers or None

    r_editor = ResourceEditor(
        patches={
            identity_provider_config: {
                "metadata": {"name": identity_provider_config.name},
                "spec": identity_providers_spec,
            }
        }
    )
    r_editor.update()


@pytest.fixture(scope="session")
def workers_type(workers_utility_pods, installing_cnv):
    if installing_cnv:
        return
    physical = ClusterHosts.Type.PHYSICAL
    virtual = ClusterHosts.Type.VIRTUAL
    for pod in workers_utility_pods:
        pod_exec = ExecCommandOnPod(utility_pods=workers_utility_pods, node=pod.node)
        out = pod_exec.exec(command="systemd-detect-virt", ignore_rc=True)
        if out == "none":
            LOGGER.info(f"Cluster workers are: {physical}")
            os.environ[WORKERS_TYPE] = physical
            return physical

    LOGGER.info(f"Cluster workers are: {virtual}")
    os.environ[WORKERS_TYPE] = virtual
    return virtual


@pytest.fixture(scope="module")
def skip_if_workers_vms(workers_type):
    if workers_type == ClusterHosts.Type.VIRTUAL:
        pytest.skip("Test should run only BM cluster")


@pytest.fixture()
def data_volume_multi_storage_scope_function(
    request,
    namespace,
    storage_class_matrix__function__,
    schedulable_nodes,
):
    yield from data_volume(
        request=request,
        namespace=namespace,
        storage_class_matrix=storage_class_matrix__function__,
        schedulable_nodes=schedulable_nodes,
    )


@pytest.fixture(scope="module")
def data_volume_multi_storage_scope_module(
    request,
    namespace,
    storage_class_matrix__module__,
    schedulable_nodes,
):
    yield from data_volume(
        request=request,
        namespace=namespace,
        storage_class_matrix=storage_class_matrix__module__,
        schedulable_nodes=schedulable_nodes,
    )


@pytest.fixture(scope="class")
def golden_image_data_volume_multi_storage_scope_class(
    admin_client,
    request,
    golden_images_namespace,
    storage_class_matrix__class__,
    schedulable_nodes,
):
    yield from data_volume(
        request=request,
        namespace=golden_images_namespace,
        storage_class_matrix=storage_class_matrix__class__,
        schedulable_nodes=schedulable_nodes,
        check_dv_exists=True,
        admin_client=admin_client,
    )


@pytest.fixture(scope="class")
def golden_image_data_source_multi_storage_scope_class(
    admin_client, golden_image_data_volume_multi_storage_scope_class
):
    yield from create_or_update_data_source(
        admin_client=admin_client, dv=golden_image_data_volume_multi_storage_scope_class
    )


@pytest.fixture()
def golden_image_data_volume_multi_storage_scope_function(
    admin_client,
    request,
    golden_images_namespace,
    storage_class_matrix__function__,
    schedulable_nodes,
):
    yield from data_volume(
        request=request,
        namespace=golden_images_namespace,
        storage_class_matrix=storage_class_matrix__function__,
        schedulable_nodes=schedulable_nodes,
        check_dv_exists=True,
        admin_client=admin_client,
    )


@pytest.fixture()
def golden_image_data_source_multi_storage_scope_function(
    admin_client, golden_image_data_volume_multi_storage_scope_function
):
    yield from create_or_update_data_source(
        admin_client=admin_client,
        dv=golden_image_data_volume_multi_storage_scope_function,
    )


@pytest.fixture()
def data_volume_scope_function(request, namespace, schedulable_nodes):
    yield from data_volume(
        request=request,
        namespace=namespace,
        storage_class=request.param["storage_class"],
        schedulable_nodes=schedulable_nodes,
    )


@pytest.fixture(scope="class")
def data_volume_scope_class(request, namespace, schedulable_nodes):
    yield from data_volume(
        request=request,
        namespace=namespace,
        storage_class=request.param["storage_class"],
        schedulable_nodes=schedulable_nodes,
    )


@pytest.fixture(scope="class")
def golden_image_data_volume_scope_class(
    request, admin_client, golden_images_namespace, schedulable_nodes
):
    yield from data_volume(
        request=request,
        namespace=golden_images_namespace,
        storage_class=request.param["storage_class"],
        schedulable_nodes=schedulable_nodes,
        check_dv_exists=True,
        admin_client=admin_client,
    )


@pytest.fixture(scope="class")
def golden_image_data_source_scope_class(
    admin_client, golden_image_data_volume_scope_class
):
    yield from create_or_update_data_source(
        admin_client=admin_client, dv=golden_image_data_volume_scope_class
    )


@pytest.fixture(scope="module")
def golden_image_data_volume_scope_module(
    request, admin_client, golden_images_namespace, schedulable_nodes
):
    yield from data_volume(
        request=request,
        namespace=golden_images_namespace,
        storage_class=request.param["storage_class"],
        schedulable_nodes=schedulable_nodes,
        check_dv_exists=True,
        admin_client=admin_client,
    )


@pytest.fixture(scope="module")
def golden_image_data_source_scope_module(
    admin_client, golden_image_data_volume_scope_module
):
    yield from create_or_update_data_source(
        admin_client=admin_client, dv=golden_image_data_volume_scope_module
    )


@pytest.fixture()
def golden_image_data_volume_scope_function(
    request, admin_client, golden_images_namespace, schedulable_nodes
):
    yield from data_volume(
        request=request,
        namespace=golden_images_namespace,
        storage_class=request.param["storage_class"],
        schedulable_nodes=schedulable_nodes,
        check_dv_exists=True,
        admin_client=admin_client,
    )


@pytest.fixture()
def golden_image_data_source_scope_function(
    admin_client, golden_image_data_volume_scope_function
):
    yield from create_or_update_data_source(
        admin_client=admin_client, dv=golden_image_data_volume_scope_function
    )


"""
VM creation from template
"""


@pytest.fixture()
def vm_instance_from_template_multi_storage_scope_function(
    request,
    unprivileged_client,
    namespace,
    data_volume_multi_storage_scope_function,
    nodes_common_cpu_model,
):
    """Calls vm_instance_from_template contextmanager

    Creates a VM from template and starts it (if requested).
    """

    with vm_instance_from_template(
        request=request,
        unprivileged_client=unprivileged_client,
        namespace=namespace,
        existing_data_volume=data_volume_multi_storage_scope_function,
        vm_cpu_model=nodes_common_cpu_model
        if request.param.get("set_vm_common_cpu")
        else None,
    ) as vm:
        yield vm


@pytest.fixture()
def golden_image_vm_instance_from_template_multi_storage_scope_function(
    request,
    unprivileged_client,
    namespace,
    golden_image_data_source_multi_storage_scope_function,
    nodes_common_cpu_model,
):
    """Calls vm_instance_from_template contextmanager

    Creates a VM from template and starts it (if requested).
    """

    with vm_instance_from_template(
        request=request,
        unprivileged_client=unprivileged_client,
        namespace=namespace,
        data_source=golden_image_data_source_multi_storage_scope_function,
        vm_cpu_model=nodes_common_cpu_model
        if request.param.get("set_vm_common_cpu")
        else None,
    ) as vm:
        yield vm


@pytest.fixture()
def golden_image_vm_instance_from_template_multi_storage_dv_scope_class_vm_scope_function(
    request,
    unprivileged_client,
    namespace,
    golden_image_data_source_multi_storage_scope_class,
    nodes_common_cpu_model,
):
    """Calls vm_instance_from_template contextmanager

    Creates a VM from template and starts it (if requested).
    VM is created with function scope whereas golden image DV is created with class scope. to be used when a number
    of tests (each creates its relevant VM) are gathered under a class and use the same golden image DV.
    """

    with vm_instance_from_template(
        request=request,
        unprivileged_client=unprivileged_client,
        namespace=namespace,
        data_source=golden_image_data_source_multi_storage_scope_class,
        vm_cpu_model=nodes_common_cpu_model
        if request.param.get("set_vm_common_cpu")
        else None,
    ) as vm:
        yield vm


@pytest.fixture(scope="class")
def golden_image_vm_instance_from_template_multi_storage_scope_class(
    request,
    unprivileged_client,
    namespace,
    golden_image_data_source_multi_storage_scope_class,
    nodes_common_cpu_model,
):
    """Calls vm_instance_from_template contextmanager

    Creates a VM from template and starts it (if requested).
    """

    with vm_instance_from_template(
        request=request,
        unprivileged_client=unprivileged_client,
        namespace=namespace,
        data_source=golden_image_data_source_multi_storage_scope_class,
        vm_cpu_model=nodes_common_cpu_model
        if request.param.get("set_vm_common_cpu")
        else None,
    ) as vm:
        yield vm


"""
Windows-specific fixtures
"""


@pytest.fixture()
def started_windows_vm(
    request,
    vm_instance_from_template_multi_storage_scope_function,
):
    wait_for_windows_vm(
        vm=vm_instance_from_template_multi_storage_scope_function,
        version=request.param["os_version"],
    )


def is_openshift(client):
    namespaces = [ns.name for ns in Namespace.get(client)]
    return "openshift-operators" in namespaces


@pytest.fixture(scope="session")
def skip_not_openshift(admin_client):
    """
    Skip test if tests run on kubernetes (and not openshift)
    """
    if not is_openshift(admin_client):
        pytest.skip("Skipping test requiring OpenShift")


@pytest.fixture(scope="session")
def worker_nodes_ipv4_false_secondary_nics(nodes_available_nics, schedulable_nodes):
    """
    Function removes ipv4 from secondary nics.
    """
    for worker_node in schedulable_nodes:
        worker_nics = nodes_available_nics[worker_node.name]
        with EthernetNetworkConfigurationPolicy(
            name=f"disable-ipv4-{name_prefix(worker_node.name)}",
            node_selector=worker_node.hostname,
            interfaces_name=worker_nics,
        ):
            LOGGER.info(
                f"selected worker node - {worker_node.name} under NNCP selected NIC information - {worker_nics} "
            )


@pytest.fixture(scope="session")
def csv_scope_session(
    is_downstream_distribution, admin_client, hco_namespace, installing_cnv
):
    if is_downstream_distribution and not installing_cnv:
        return utilities.hco.get_installed_hco_csv(
            admin_client=admin_client, hco_namespace=hco_namespace
        )


@pytest.fixture(scope="session")
def cnv_current_version(installing_cnv, csv_scope_session):
    if installing_cnv:
        return CNV_NOT_INSTALLED
    if csv_scope_session:
        return csv_scope_session.instance.spec.version


@pytest.fixture(scope="session")
def hco_namespace(admin_client, installing_cnv):
    if not installing_cnv:
        return utilities.hco.get_hco_namespace(
            admin_client=admin_client, namespace=py_config["hco_namespace"]
        )


@pytest.fixture(scope="session")
def worker_node1(schedulable_nodes):
    # Get first worker nodes out of schedulable_nodes list
    return schedulable_nodes[0]


@pytest.fixture(scope="session")
def worker_node2(schedulable_nodes):
    # Get second worker nodes out of schedulable_nodes list
    return schedulable_nodes[1]


@pytest.fixture(scope="session")
def worker_node3(schedulable_nodes):
    # Get third worker nodes out of schedulable_nodes list
    return schedulable_nodes[2]


@pytest.fixture(scope="session")
def sriov_namespace():
    return Namespace(name=py_config["sriov_namespace"])


@pytest.fixture(scope="session")
def sriov_nodes_states(
    skip_when_no_sriov, admin_client, sriov_namespace, sriov_workers
):
    sriov_nns_list = [
        SriovNetworkNodeState(
            client=admin_client, namespace=sriov_namespace.name, name=worker.name
        )
        for worker in sriov_workers
    ]
    return sriov_nns_list


@pytest.fixture(scope="session")
def sriov_workers(schedulable_nodes):
    sriov_worker_label = "feature.node.kubernetes.io/network-sriov.capable"
    yield [
        node
        for node in schedulable_nodes
        if node.labels.get(sriov_worker_label) == "true"
    ]


@pytest.fixture(scope="session")
def vlan_base_iface(worker_node1, nodes_available_nics):
    # Select the last NIC from the list as a way to ensure that the selected NIC
    # is not already used (e.g. as a bond's port).
    return nodes_available_nics[worker_node1.name][-1]


@pytest.fixture(scope="session")
def sriov_iface_with_vlan(sriov_ifaces, vlan_base_iface):
    for interface in sriov_ifaces:
        if interface["name"] == vlan_base_iface:
            return interface
    raise SriovIfaceNotFound(
        f"No sriov interface with vlan found. vlan base iface is {vlan_base_iface}, "
        f"sriov ifaces is {sriov_ifaces}"
    )


@pytest.fixture(scope="session")
def sriov_ifaces(sriov_nodes_states, workers_utility_pods):
    node = sriov_nodes_states[0]
    state_up = Resource.Interface.State.UP
    ifaces_list = [
        iface
        for iface in node.instance.status.interfaces
        if (
            iface.totalvfs
            and ExecCommandOnPod(
                utility_pods=workers_utility_pods, node=node
            ).interface_status(interface=iface.name)
            == state_up
        )
    ]

    if not ifaces_list:
        raise SriovIfaceNotFound(
            f"no sriov interface with '{state_up}' status was found, "
            f"please make sure at least one sriov interface is {state_up}"
        )

    return ifaces_list


@pytest.fixture(scope="session")
def sriov_node_policy(sriov_nodes_states, sriov_ifaces, sriov_namespace):
    yield from create_sriov_node_policy(
        nncp_name="test-sriov-policy",
        namespace=sriov_namespace.name,
        sriov_iface=sriov_ifaces[0],
        sriov_nodes_states=sriov_nodes_states,
        sriov_resource_name="sriov_net",
    )


@pytest.fixture(scope="session")
def mac_pool(hco_namespace):
    return MacPool(
        kmp_range=ConfigMap(
            namespace=hco_namespace.name, name=KUBEMACPOOL_MAC_RANGE_CONFIG
        ).instance["data"]
    )


def _skip_access_mode_rwo(storage_class_matrix):
    if (
        storage_class_matrix[[*storage_class_matrix][0]]["access_mode"]
        == PersistentVolumeClaim.AccessMode.RWO
    ):
        pytest.skip(
            msg="Skipping when access_mode is RWO; possible reason: cannot migrate VMI with non-shared PVCs"
        )


@pytest.fixture()
def skip_access_mode_rwo_scope_function(storage_class_matrix__function__):
    _skip_access_mode_rwo(storage_class_matrix=storage_class_matrix__function__)


@pytest.fixture(scope="class")
def skip_access_mode_rwo_scope_class(storage_class_matrix__class__):
    _skip_access_mode_rwo(storage_class_matrix=storage_class_matrix__class__)


@pytest.fixture(scope="session")
def nodes_common_cpu_model_list(schedulable_nodes):
    nodes_common_cpu_model = set()

    for node in schedulable_nodes:
        node_cpu_model_list = []
        for label, value in node.labels.items():
            match_object = re.match(rf"{CPU_MODEL_LABEL_PREFIX}/(.*)", label)
            if match_object and value == "true":
                node_cpu_model_list.append(match_object.group(1))
        if not nodes_common_cpu_model:
            nodes_common_cpu_model = set(node_cpu_model_list)
        nodes_common_cpu_model = nodes_common_cpu_model.intersection(
            set(node_cpu_model_list)
        )
    if nodes_common_cpu_model:
        return list(nodes_common_cpu_model)
    raise CommonNodesCpusNotFoundError(nodes=schedulable_nodes)


@pytest.fixture(scope="session")
def nodes_cpu_architecture(schedulable_nodes):
    if schedulable_nodes[0].labels.get("cpu-vendor.node.kubevirt.io/AMD"):
        return AMD
    else:
        return INTEL


@pytest.fixture(scope="session")
def nodes_common_cpu_model(nodes_common_cpu_model_list, nodes_cpu_architecture):
    """
    Get a CPU model that is common for all nodes
    """
    # Due to BZ 2122283 <skip-bug-check> (targeted to 4.13) need to exclude Opteron_G1 and Opteron_G2
    # CPU models from the common CPUs list
    nodes_common_cpu_model_list = (
        [model for model in nodes_common_cpu_model_list if model not in AMD_CPU_MODELS]
        if nodes_cpu_architecture == INTEL
        else nodes_common_cpu_model_list
    )

    return nodes_common_cpu_model_list[0]


@pytest.fixture(scope="session")
def golden_images_namespace(
    admin_client,
):
    for ns in Namespace.get(
        name=py_config["golden_images_namespace"],
        dyn_client=admin_client,
    ):
        return ns


@pytest.fixture(scope="session")
def golden_images_cluster_role_edit(
    admin_client,
):
    for cluster_role in ClusterRole.get(
        name="os-images.kubevirt.io:edit",
        dyn_client=admin_client,
    ):
        return cluster_role


@pytest.fixture()
def golden_images_edit_rolebinding(
    golden_images_namespace,
    golden_images_cluster_role_edit,
):
    with RoleBinding(
        name="role-bind-create-dv",
        namespace=golden_images_namespace.name,
        subjects_kind="User",
        subjects_name="unprivileged-user",
        subjects_namespace=golden_images_namespace.name,
        role_ref_kind=golden_images_cluster_role_edit.kind,
        role_ref_name=golden_images_cluster_role_edit.name,
    ) as role_binding:
        yield role_binding


@pytest.fixture(scope="session")
def hosts_common_available_ports(nodes_available_nics):
    """
    Get list of common ports from nodes_available_nics.

    nodes_available_nics like
    [['ens3', 'ens4', 'ens6', 'ens5'],
    ['ens3', 'ens8', 'ens6', 'ens7'],
    ['ens3', 'ens8', 'ens6', 'ens7']]

    will return ['ens3', 'ens6']
    """
    nics_list = list(
        set.intersection(*[set(_list) for _list in nodes_available_nics.values()])
    )
    nics_list.sort()
    LOGGER.info(f"Hosts common available NICs: {nics_list}")
    return nics_list


@pytest.fixture(scope="session")
def default_sc(admin_client):
    """
    Get default Storage Class defined
    """
    try:
        yield default_storage_class(client=admin_client)
    except ValueError:
        yield


@pytest.fixture()
def hyperconverged_resource_scope_function(admin_client, hco_namespace):
    return get_hyperconverged_resource(
        client=admin_client, hco_ns_name=hco_namespace.name
    )


@pytest.fixture(scope="class")
def hyperconverged_resource_scope_class(admin_client, hco_namespace):
    return get_hyperconverged_resource(
        client=admin_client, hco_ns_name=hco_namespace.name
    )


@pytest.fixture(scope="module")
def hyperconverged_resource_scope_module(admin_client, hco_namespace, installing_cnv):
    if not installing_cnv:
        return get_hyperconverged_resource(
            client=admin_client, hco_ns_name=hco_namespace.name
        )


@pytest.fixture(scope="session")
def hyperconverged_resource_scope_session(admin_client, hco_namespace, installing_cnv):
    if not installing_cnv:
        return get_hyperconverged_resource(
            client=admin_client, hco_ns_name=hco_namespace.name
        )


@pytest.fixture()
def kubevirt_hyperconverged_spec_scope_function(
    admin_client, hco_namespace, installing_cnv
):
    if not installing_cnv:
        return get_kubevirt_hyperconverged_spec(
            admin_client=admin_client, hco_namespace=hco_namespace
        )


@pytest.fixture(scope="module")
def kubevirt_hyperconverged_spec_scope_module(admin_client, hco_namespace):
    return get_kubevirt_hyperconverged_spec(
        admin_client=admin_client, hco_namespace=hco_namespace
    )


@pytest.fixture()
def kubevirt_config(kubevirt_hyperconverged_spec_scope_function):
    return kubevirt_hyperconverged_spec_scope_function["configuration"]


@pytest.fixture(scope="module")
def kubevirt_config_scope_module(kubevirt_hyperconverged_spec_scope_module):
    return kubevirt_hyperconverged_spec_scope_module["configuration"]


@pytest.fixture()
def kubevirt_feature_gates(kubevirt_config):
    return kubevirt_config["developerConfiguration"]["featureGates"]


@pytest.fixture(scope="session")
def skip_when_no_sriov(admin_client):
    try:
        list(
            CustomResourceDefinition.get(
                dyn_client=admin_client,
                name="sriovnetworknodestates.sriovnetwork.openshift.io",
            )
        )
    except NotFoundError:
        pytest.skip("Cluster without SR-IOV support")


@pytest.fixture(scope="class")
def ovs_daemonset(admin_client, hco_namespace):
    return wait_for_ovs_daemonset_resource(
        admin_client=admin_client, hco_namespace=hco_namespace
    )


@pytest.fixture()
def hyperconverged_ovs_annotations_fetched(hyperconverged_resource_scope_function):
    return get_hyperconverged_ovs_annotations(
        hyperconverged=hyperconverged_resource_scope_function
    )


@pytest.fixture(scope="session")
def network_addons_config_scope_session(admin_client):
    nac = list(NetworkAddonsConfig.get(dyn_client=admin_client))
    assert nac, "There should be one NetworkAddonsConfig CR."
    return nac[0]


@pytest.fixture(scope="session")
def ocs_storage_class(cluster_storage_classes):
    """
    Get the OCS storage class if configured
    """
    for sc in cluster_storage_classes:
        if sc.name == StorageClassNames.CEPH_RBD:
            return sc


@pytest.fixture(scope="session")
def skip_test_if_no_ocs_sc(ocs_storage_class):
    """
    Skip test if no OCS storage class available
    """
    if not ocs_storage_class:
        pytest.skip("Skipping test, OCS storage class is not deployed")


@pytest.fixture(scope="session")
def skip_test_if_no_nfs_sc(cluster_storage_classes_names):
    """
    Skip test if no NFS storage class available
    """
    if StorageClassNames.NFS not in cluster_storage_classes_names:
        pytest.skip(
            f"Skipping test, {StorageClassNames.NFS} storage class is not deployed,"
            f"deployed storage classes: {cluster_storage_classes_names}"
        )


@pytest.fixture(scope="session")
def skip_test_if_no_csi_basic_sc(cluster_storage_classes_names):
    """
    Skip test if no CSI basic storage class available
    """
    if HOSTPATH_CSI_BASIC not in cluster_storage_classes_names:
        pytest.skip(
            f"Skipping test, {HOSTPATH_CSI_BASIC} basic storage class is not deployed,"
            f"deployed storage classes: {cluster_storage_classes_names}"
        )


@pytest.fixture(scope="session")
def hyperconverged_ovs_annotations_enabled_scope_session(
    admin_client,
    hco_namespace,
    hyperconverged_resource_scope_session,
    network_addons_config_scope_session,
):
    yield from enable_hyperconverged_ovs_annotations(
        admin_client=admin_client,
        hco_namespace=hco_namespace,
        hyperconverged_resource=hyperconverged_resource_scope_session,
        network_addons_config=network_addons_config_scope_session,
    )

    # Make sure all ovs pods are deleted:
    wait_for_ovs_status(
        network_addons_config=network_addons_config_scope_session, status=False
    )
    wait_for_pods_deletion(
        pods=get_pods(
            dyn_client=admin_client,
            namespace=hco_namespace,
            label="app=ovs-cni",
        )
    )


@pytest.fixture(scope="session")
def cluster_storage_classes(admin_client):
    return list(StorageClass.get(dyn_client=admin_client))


@pytest.fixture(scope="session")
def cluster_storage_classes_names(cluster_storage_classes):
    return [sc.name for sc in cluster_storage_classes]


@pytest.fixture()
def removed_default_storage_classes(admin_client, cluster_storage_classes):
    sc_resources = []
    for sc in cluster_storage_classes:
        if (
            sc.instance.metadata.get("annotations", {}).get(
                StorageClass.Annotations.IS_DEFAULT_CLASS
            )
            == "true"
        ):
            sc_resources.append(
                ResourceEditor(
                    patches={
                        sc: {
                            "metadata": {
                                "annotations": {
                                    StorageClass.Annotations.IS_DEFAULT_CLASS: "false"
                                },
                                "name": sc.name,
                            }
                        }
                    }
                )
            )
    for editor in sc_resources:
        editor.update(backup_resources=True)
    yield
    for editor in sc_resources:
        editor.restore()


@pytest.fixture(scope="class")
def hyperconverged_with_node_placement(
    request, admin_client, hco_namespace, hyperconverged_resource_scope_class
):
    """
    Update HCO CR with infrastructure and workloads spec.
    """
    infra_placement = request.param["infra"]
    workloads_placement = request.param["workloads"]

    LOGGER.info("Fetching HCO to save its initial node placement configuration ")
    initial_infra = hyperconverged_resource_scope_class.instance.to_dict()["spec"].get(
        "infra", {}
    )
    initial_workloads = hyperconverged_resource_scope_class.instance.to_dict()[
        "spec"
    ].get("workloads", {})
    yield utilities.hco.apply_np_changes(
        admin_client=admin_client,
        hco=hyperconverged_resource_scope_class,
        hco_namespace=hco_namespace,
        infra_placement=infra_placement,
        workloads_placement=workloads_placement,
    )
    LOGGER.info("Revert to initial HCO node placement configuration ")
    utilities.hco.apply_np_changes(
        admin_client=admin_client,
        hco=hyperconverged_resource_scope_class,
        hco_namespace=hco_namespace,
        infra_placement=initial_infra,
        workloads_placement=initial_workloads,
    )


@pytest.fixture(scope="module")
def hostpath_provisioner_scope_module():
    yield HostPathProvisioner(name=HostPathProvisioner.Name.HOSTPATH_PROVISIONER)


@pytest.fixture(scope="session")
def hostpath_provisioner_scope_session():
    yield HostPathProvisioner(name=HostPathProvisioner.Name.HOSTPATH_PROVISIONER)


@pytest.fixture(scope="module")
def cnv_pods(admin_client, hco_namespace):
    yield list(Pod.get(dyn_client=admin_client, namespace=hco_namespace.name))


@pytest.fixture(scope="session")
def cluster_sanity_scope_session(
    request,
    nodes,
    cluster_storage_classes_names,
    admin_client,
    hco_namespace,
    junitxml_plugin,
    hyperconverged_resource_scope_session,
    installing_cnv,
):
    """
    Performs various cluster level checks, e.g.: storage class validation, node state, as well as all cnv pod
    check to ensure all are in 'Running' state, to determine current state of cluster
    """
    if not installing_cnv:
        cluster_sanity(
            request=request,
            admin_client=admin_client,
            cluster_storage_classes_names=cluster_storage_classes_names,
            nodes=nodes,
            hco_namespace=hco_namespace,
            junitxml_property=junitxml_plugin,
            hco_status_conditions=hyperconverged_resource_scope_session.instance.status.conditions,
            expected_hco_status=DEFAULT_HCO_CONDITIONS,
        )


@pytest.fixture(scope="module")
def cluster_sanity_scope_module(
    request,
    nodes,
    cluster_storage_classes_names,
    admin_client,
    hco_namespace,
    junitxml_plugin,
    hyperconverged_resource_scope_session,
    installing_cnv,
):
    """
    Performs various cluster level checks, e.g.: storage class validation, node state, as well as all cnv pod
    check to ensure all are in 'Running' state, to determine current state of cluster
    """
    if not installing_cnv:
        cluster_sanity(
            request=request,
            admin_client=admin_client,
            cluster_storage_classes_names=cluster_storage_classes_names,
            nodes=nodes,
            hco_namespace=hco_namespace,
            junitxml_property=junitxml_plugin,
            hco_status_conditions=hyperconverged_resource_scope_session.instance.status.conditions,
            expected_hco_status=DEFAULT_HCO_CONDITIONS,
        )


@pytest.fixture(scope="session")
def kmp_vm_label(admin_client):
    kmp_webhook_config = MutatingWebhookConfiguration(
        client=admin_client, name="kubemacpool-mutator"
    )

    for webhook in kmp_webhook_config.instance.to_dict()["webhooks"]:
        if webhook["name"] == KMP_VM_ASSIGNMENT_LABEL:
            return {
                ldict["key"]: ldict["values"][0]
                for ldict in webhook["namespaceSelector"]["matchExpressions"]
                if ldict["key"] == KMP_VM_ASSIGNMENT_LABEL
            }

    raise ResourceNotFoundError(f"Webhook {KMP_VM_ASSIGNMENT_LABEL} was not found")


@pytest.fixture(scope="class")
def kmp_enabled_ns(kmp_vm_label):
    # Enabling label "allocate" (or any other non-configured label) - Allocates.
    kmp_vm_label[KMP_VM_ASSIGNMENT_LABEL] = KMP_ENABLED_LABEL
    yield from create_ns(name="kmp-enabled", labels=kmp_vm_label)


@pytest.fixture(scope="session")
def cdi(hco_namespace):
    cdi = CDI(name=CDI_KUBEVIRT_HYPERCONVERGED)
    assert cdi.instance is not None
    yield cdi


@pytest.fixture(scope="session")
def cdi_config():
    cdi_config = CDIConfig(name="config")
    assert cdi_config.instance is not None
    return cdi_config


@pytest.fixture(scope="session")
def prometheus():
    return Prometheus()


@pytest.fixture()
def cdi_spec(cdi):
    return cdi.instance.to_dict()["spec"]


@pytest.fixture()
def hco_spec(hyperconverged_resource_scope_function):
    return hyperconverged_resource_scope_function.instance.to_dict()["spec"]


@pytest.fixture(scope="module")
def is_post_cnv_upgrade_cluster(admin_client, hco_namespace):
    return (
        len(
            list(
                InstallPlan.get(
                    dyn_client=admin_client,
                    namespace=hco_namespace.name,
                )
            )
        )
        > 1
    )


@pytest.fixture(scope="session")
def cluster_info(
    admin_client,
    is_downstream_distribution,
    is_upstream_distribution,
    installing_cnv,
    openshift_current_version,
    cnv_current_version,
    hco_image,
    ocs_current_version,
    kubevirt_resource_scope_session,
    ipv6_supported_cluster,
    ipv4_supported_cluster,
    workers_type,
):
    title = "\nCluster info:\n"
    if is_downstream_distribution:
        virtctl_client_version, virtctl_server_version = None, None
        if not installing_cnv:
            virtctl_client_version, virtctl_server_version = (
                run_virtctl_command(command=["version"])[1].strip().splitlines()
            )

        LOGGER.info(
            f"{title}"
            f"\tOpenshift version: {openshift_current_version}\n"
            f"\tCNV version: {cnv_current_version}\n"
            f"\tHCO image: {hco_image}\n"
            f"\tOCS version: {ocs_current_version}\n"
            f"\tCNI type: {get_cluster_cni_type(admin_client=admin_client)}\n"
            f"\tWorkers type: {workers_type}\n"
            f"\tIPv4 cluster: {ipv4_supported_cluster}\n"
            f"\tIPv6 cluster: {ipv6_supported_cluster}\n"
            f"\tVirtctl version: \n\t{virtctl_client_version}\n\t{virtctl_server_version}\n"
        )
    elif is_upstream_distribution:
        LOGGER.info(
            f"{title}"
            "Kubevirt version: "
            f"{kubevirt_resource_scope_session.instance.status.targetKubeVirtVersion}"
        )


@pytest.fixture(scope="session")
def ocs_current_version(ocs_storage_class, admin_client):
    if ocs_storage_class:
        for csv in ClusterServiceVersion.get(
            dyn_client=admin_client,
            namespace="openshift-storage",
            label_selector=f"{ClusterServiceVersion.ApiGroup.OPERATORS_COREOS_COM}/ocs-operator.openshift-storage",
        ):
            return csv.instance.spec.version


@pytest.fixture(scope="session")
def openshift_current_version(is_downstream_distribution, admin_client):
    if is_downstream_distribution:
        return (
            get_clusterversion(dyn_client=admin_client)
            .instance.status.history[0]
            .version
        )


@pytest.fixture(scope="session")
def hco_image(
    is_downstream_distribution,
    admin_client,
    installing_cnv,
    cnv_subscription_scope_session,
):
    if installing_cnv:
        return CNV_NOT_INSTALLED
    if is_downstream_distribution:
        source_name = cnv_subscription_scope_session.instance.spec.source
        for cs in CatalogSource.get(
            dyn_client=admin_client,
            name=source_name,
            namespace=py_config["marketplace_namespace"],
        ):
            return cs.instance.spec.image


@pytest.fixture(scope="session")
def cnv_subscription_scope_session(
    is_downstream_distribution,
    admin_client,
    installing_cnv,
    hco_namespace,
):
    if is_downstream_distribution and not installing_cnv:
        return get_subscription(
            admin_client=admin_client,
            namespace=hco_namespace.name,
            subscription_name=py_config["hco_subscription"] or HCO_SUBSCRIPTION,
        )


@pytest.fixture(scope="session")
def kubevirt_resource_scope_session(admin_client, installing_cnv, hco_namespace):
    if not installing_cnv:
        return get_hyperconverged_kubevirt(
            admin_client=admin_client, hco_namespace=hco_namespace
        )


@pytest.fixture(scope="session")
def is_upstream_distribution():
    return py_config["distribution"] == "upstream"


@pytest.fixture(scope="session")
def is_downstream_distribution():
    return py_config["distribution"] == "downstream"


@pytest.fixture(scope="session")
def junitxml_plugin(request, record_testsuite_property):
    return (
        record_testsuite_property
        if request.config.pluginmanager.has_plugin("junitxml")
        else None
    )


@pytest.fixture(scope="module")
def base_templates(admin_client):
    # Exclude SAP HANA template (template's content is currently different from base templates)
    # TODO: re-add template when all open issues are resolved.
    base_templates = get_base_templates_list(client=admin_client)
    base_templates = [
        template
        for template in base_templates
        if Template.Workload.SAPHANA not in template.name
    ]

    return base_templates


@pytest.fixture(scope="package")
def must_gather_image_url(is_upstream_distribution, csv_scope_session):
    if is_upstream_distribution:
        return "quay.io/kubevirt/must-gather"
    LOGGER.info(f"Csv name is : {csv_scope_session.name}")
    must_gather_image = [
        image["image"]
        for image in csv_scope_session.instance.spec.relatedImages
        if "must-gather" in image["name"]
    ]
    assert must_gather_image, (
        f"Csv: {csv_scope_session.name}, "
        f"related images: {csv_scope_session.instance.spec.relatedImages} "
        "does not have must gather image."
    )

    return must_gather_image[0]


@pytest.fixture
def term_handler_scope_function():
    orig = signal(SIGTERM, getsignal(SIGINT))
    yield
    signal(SIGTERM, orig)


@pytest.fixture(scope="class")
def term_handler_scope_class():
    orig = signal(SIGTERM, getsignal(SIGINT))
    yield
    signal(SIGTERM, orig)


@pytest.fixture(scope="module")
def term_handler_scope_module():
    orig = signal(SIGTERM, getsignal(SIGINT))
    yield
    signal(SIGTERM, orig)


@pytest.fixture(scope="session")
def term_handler_scope_session():
    orig = signal(SIGTERM, getsignal(SIGINT))
    yield
    signal(SIGTERM, orig)


@pytest.fixture(scope="session")
def upgrade_bridge_on_all_nodes(
    skip_if_no_multinic_nodes,
    label_schedulable_nodes,
    hosts_common_available_ports,
):
    with network_device(
        interface_type=LINUX_BRIDGE,
        nncp_name="upgrade-bridge",
        interface_name="br1upgrade",
        node_selector_labels=NODE_TYPE_WORKER_LABEL,
        ports=[hosts_common_available_ports[0]],
    ) as br:
        yield br


@pytest.fixture(scope="session")
def bridge_on_one_node(worker_node1):
    with network_device(
        interface_type=LINUX_BRIDGE,
        nncp_name="upgrade-br-marker",
        interface_name="upg-br-mark",
        node_selector=worker_node1.name,
    ) as br:
        yield br


@pytest.fixture(scope="session")
def upgrade_bridge_marker_nad(bridge_on_one_node, kmp_enabled_namespace):
    with network_nad(
        nad_type=LINUX_BRIDGE,
        nad_name=bridge_on_one_node.bridge_name,
        interface_name=bridge_on_one_node.bridge_name,
        namespace=kmp_enabled_namespace,
    ) as nad:
        yield nad


@pytest.fixture(scope="session")
def running_vm_upgrade_a(
    unprivileged_client,
    upgrade_bridge_marker_nad,
    kmp_enabled_namespace,
    upgrade_br1test_nad,
):
    name = "vm-upgrade-a"
    with cluster_resource(VirtualMachineForTests)(
        name=name,
        namespace=kmp_enabled_namespace.name,
        networks={upgrade_bridge_marker_nad.name: upgrade_bridge_marker_nad.name},
        interfaces=[upgrade_bridge_marker_nad.name],
        client=unprivileged_client,
        cloud_init_data=cloud_init(ip_address="10.200.100.1"),
        body=fedora_vm_body(name=name),
        eviction=None,
    ) as vm:
        running_vm(vm=vm, wait_for_cloud_init=True)
        yield vm


@pytest.fixture(scope="session")
def running_vm_upgrade_b(
    unprivileged_client,
    upgrade_bridge_marker_nad,
    kmp_enabled_namespace,
    upgrade_br1test_nad,
):
    name = "vm-upgrade-b"
    with cluster_resource(VirtualMachineForTests)(
        name=name,
        namespace=kmp_enabled_namespace.name,
        networks={upgrade_bridge_marker_nad.name: upgrade_bridge_marker_nad.name},
        interfaces=[upgrade_bridge_marker_nad.name],
        client=unprivileged_client,
        cloud_init_data=cloud_init(ip_address="10.200.100.2"),
        body=fedora_vm_body(name=name),
        eviction=None,
    ) as vm:
        running_vm(vm=vm, wait_for_cloud_init=True)
        yield vm


@pytest.fixture(scope="session")
def upgrade_br1test_nad(upgrade_namespace_scope_session, upgrade_bridge_on_all_nodes):
    with network_nad(
        nad_type=LINUX_BRIDGE,
        nad_name=upgrade_bridge_on_all_nodes.bridge_name,
        interface_name=upgrade_bridge_on_all_nodes.bridge_name,
        namespace=upgrade_namespace_scope_session,
    ) as nad:
        yield nad


@pytest.fixture(scope="session")
def dvs_for_upgrade(admin_client, worker_node1, rhel_latest_os_params):
    dvs_list = []
    for sc in py_config["storage_class_matrix"]:
        storage_class = [*sc][0]
        dv = DataVolume(
            client=admin_client,
            name=f"dv-for-product-upgrade-{storage_class}",
            namespace=py_config["golden_images_namespace"],
            source="http",
            storage_class=storage_class,
            volume_mode=sc[storage_class]["volume_mode"],
            access_modes=sc[storage_class]["access_mode"],
            url=rhel_latest_os_params["rhel_image_path"],
            size=rhel_latest_os_params["rhel_dv_size"],
            bind_immediate_annotation=True,
            hostpath_node=worker_node1.name
            if sc_is_hpp_with_immediate_volume_binding(sc=storage_class)
            else None,
            privileged_client=admin_client,
        )
        dv.create()
        dvs_list.append(dv)
    for dv in dvs_list:
        dv.wait_for_dv_success()

    yield dvs_list

    for dv in dvs_list:
        dv.clean_up()


@pytest.fixture(scope="session")
def vm_bridge_networks(upgrade_bridge_on_all_nodes):
    return {
        upgrade_bridge_on_all_nodes.bridge_name: upgrade_bridge_on_all_nodes.bridge_name
    }


@pytest.fixture(scope="session")
def cnv_upgrade_stream(admin_client, pytestconfig, cnv_current_version, is_eus_upgrade):
    """
    Verify if the upgrade can be performed by comparing the current and target versions.

    Args:
        admin_client: The admin client instance.
        pytestconfig: The pytest configuration object.
        cnv_current_version: The current CNV version.
    """
    if not is_eus_upgrade:
        target_version = pytestconfig.option.cnv_version
        upgrade_stream = determine_upgrade_stream(
            current_version=cnv_current_version, target_version=target_version
        )

        LOGGER.info(
            f"CNV upgrade:\n"
            f"Current version: {cnv_current_version},\n"
            f"Target version: {target_version},\n"
            f"Upgrade stream: {upgrade_stream},\n"
        )
        return upgrade_stream


def determine_upgrade_stream(current_version, target_version):
    current_cnv_version = packaging.version.parse(version=current_version.split("-")[0])
    target_cnv_version = packaging.version.parse(version=target_version.split("-")[0])

    if current_cnv_version.major < target_cnv_version.major:
        return UpgradeStreams.X_STREAM
    elif current_cnv_version.minor < target_cnv_version.minor:
        return UpgradeStreams.Y_STREAM
    elif current_cnv_version.micro < target_cnv_version.micro:
        return UpgradeStreams.Z_STREAM
    elif HOTFIX_STR in current_version:
        # if we reach here, this is an upgrade out of hotfix to next z-stream
        return UpgradeStreams.Z_STREAM
    else:
        if target_cnv_version <= current_cnv_version:
            # Upgrade only if a newer CNV version is requested
            raise ValueError(
                f"Cannot upgrade to older/identical versions,"
                f"current: {cnv_current_version} target: {target_cnv_version}"
            )
        raise ValueError(
            f"Unknown upgrade stream. Current cnv version: {current_cnv_version}, "
            f"target cnv version: {target_cnv_version}."
        )


@pytest.fixture(scope="session")
def upgrade_namespace_scope_session(admin_client, unprivileged_client):
    yield from create_ns(
        unprivileged_client=unprivileged_client,
        admin_client=admin_client,
        name="test-upgrade-namespace",
    )


@pytest.fixture(scope="session")
def kmp_enabled_namespace(kmp_vm_label, unprivileged_client, admin_client):
    # Enabling label "allocate" (or any other non-configured label) - Allocates.
    kmp_vm_label[KMP_VM_ASSIGNMENT_LABEL] = KMP_ENABLED_LABEL
    yield from create_ns(
        name="kmp-enabled-for-upgrade",
        labels=kmp_vm_label,
        unprivileged_client=unprivileged_client,
        admin_client=admin_client,
    )


@pytest.fixture(scope="session")
def rhel_latest_os_params():
    """This fixture is needed as during collection pytest_testconfig is empty.
    os_params or any globals using py_config in conftest cannot be used.
    """
    latest_rhel_dict = py_config["latest_rhel_os_dict"]
    return {
        "rhel_image_path": f"{get_images_server_url(schema='http')}{latest_rhel_dict['image_path']}",
        "rhel_dv_size": latest_rhel_dict["dv_size"],
        "rhel_template_labels": latest_rhel_dict["template_labels"],
    }


@pytest.fixture(scope="session")
def hco_target_version(cnv_target_version):
    return (
        get_hco_version_name(cnv_target_version=cnv_target_version)
        if cnv_target_version
        else None
    )


@pytest.fixture(scope="session")
def eus_hco_target_version(is_eus_upgrade, eus_target_cnv_version):
    if is_eus_upgrade:
        return get_hco_version_name(cnv_target_version=eus_target_cnv_version)


@pytest.fixture(scope="session")
def cnv_target_version(pytestconfig):
    return pytestconfig.option.cnv_version


@pytest.fixture(scope="session")
def is_eus_upgrade(pytestconfig):
    return pytestconfig.option.upgrade == "eus"


@pytest.fixture()
def ssp_resource_scope_function(admin_client, hco_namespace):
    return get_ssp_resource(admin_client=admin_client, namespace=hco_namespace)


@pytest.fixture(scope="session")
def cluster_service_network(is_downstream_distribution, admin_client):
    if is_downstream_distribution:
        return Network(
            client=admin_client, name="cluster"
        ).instance.status.serviceNetwork


@pytest.fixture(scope="session")
def ipv4_supported_cluster(cluster_service_network):
    if cluster_service_network:
        return any(
            [ipaddress.ip_network(ip).version == 4 for ip in cluster_service_network]
        )


@pytest.fixture(scope="session")
def ipv6_supported_cluster(cluster_service_network):
    if cluster_service_network:
        return any(
            [ipaddress.ip_network(ip).version == 6 for ip in cluster_service_network]
        )


@pytest.fixture()
def disabled_common_boot_image_import_feature_gate_scope_function(
    admin_client,
    hyperconverged_resource_scope_function,
    golden_images_namespace,
    golden_images_data_import_crons_scope_function,
):
    yield from utilities.hco.disable_common_boot_image_import_feature_gate(
        admin_client=admin_client,
        hco_resource=hyperconverged_resource_scope_function,
        golden_images_namespace=golden_images_namespace,
        golden_images_data_import_crons=golden_images_data_import_crons_scope_function,
    )


@pytest.fixture()
def golden_images_data_import_crons_scope_function(
    admin_client, golden_images_namespace
):
    return get_data_import_crons(
        admin_client=admin_client, namespace=golden_images_namespace
    )


@pytest.fixture(scope="session")
def sno_cluster(admin_client):
    return (
        Infrastructure(
            client=admin_client, name="cluster"
        ).instance.status.infrastructureTopology
        == "SingleReplica"
    )


@pytest.fixture(scope="session")
def label_schedulable_nodes(schedulable_nodes):
    yield from label_nodes(nodes=schedulable_nodes, labels=NODE_TYPE_WORKER_LABEL)


@pytest.fixture(scope="class")
def disabled_common_boot_image_import_feature_gate_scope_class(
    admin_client,
    hyperconverged_resource_scope_class,
    golden_images_namespace,
    golden_images_data_import_crons_scope_class,
):
    yield from utilities.hco.disable_common_boot_image_import_feature_gate(
        admin_client=admin_client,
        hco_resource=hyperconverged_resource_scope_class,
        golden_images_namespace=golden_images_namespace,
        golden_images_data_import_crons=golden_images_data_import_crons_scope_class,
    )


@pytest.fixture(scope="class")
def golden_images_data_import_crons_scope_class(admin_client, golden_images_namespace):
    return get_data_import_crons(
        admin_client=admin_client, namespace=golden_images_namespace
    )


@pytest.fixture(scope="session")
def skip_if_not_sno_cluster(sno_cluster):
    if not sno_cluster:
        pytest.skip("Skip test on non-SNO cluster")


@pytest.fixture(scope="session")
def skip_if_sno_cluster(sno_cluster):
    if sno_cluster:
        pytest.skip("Skip test on SNO cluster")


@pytest.fixture()
def virt_pods_with_running_status(admin_client, hco_namespace):
    return get_all_virt_pods_with_running_status(
        dyn_client=admin_client, hco_namespace=hco_namespace
    )


@pytest.fixture()
def disabled_virt_operator(admin_client, hco_namespace, virt_pods_with_running_status):
    virt_pods_count_before_disabling_virt_operator = len(
        virt_pods_with_running_status.keys()
    )

    with scale_deployment_replicas(
        deployment_name=VIRT_OPERATOR,
        namespace=hco_namespace.name,
        replica_count=0,
    ):
        yield

    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_5MIN,
        sleep=5,
        func=get_all_virt_pods_with_running_status,
        dyn_client=admin_client,
        hco_namespace=hco_namespace,
    )
    sample = None
    try:
        for sample in samples:
            if len(sample.keys()) == virt_pods_count_before_disabling_virt_operator:
                return True
    except TimeoutExpiredError:
        LOGGER.error(
            f"After restoring replicas for {VIRT_OPERATOR},"
            f"{virt_pods_with_running_status} virt pods were expected to be in running state."
            f"Here are available virt pods:{sample}"
        )
        raise


@pytest.fixture(scope="session")
def bin_directory(tmpdir_factory):
    return tmpdir_factory.mktemp("bin")


@pytest.fixture(scope="session")
def os_path_environment():
    return os.environ["PATH"]


@pytest.fixture(scope="session")
def virtctl_binary(
    is_upstream_distribution, installing_cnv, os_path_environment, bin_directory
):
    if installing_cnv or is_upstream_distribution:
        return
    installed_virtctl = os.environ.get("CNV_TESTS_VIRTCTL_BIN")
    if installed_virtctl:
        LOGGER.warning(f"Using previously installed: {installed_virtctl}")
        return
    return download_file_from_cluster(
        get_console_spec_links_name=VIRTCTL_CLI_DOWNLOADS, dest_dir=bin_directory
    )


@pytest.fixture(scope="session")
def oc_binary(is_upstream_distribution, os_path_environment, bin_directory):
    if is_upstream_distribution:
        return
    installed_oc = os.environ.get("CNV_TESTS_OC_BIN")
    if installed_oc:
        LOGGER.warning(f"Using previously installed: {installed_oc}")
        return
    return download_file_from_cluster(
        get_console_spec_links_name="oc-cli-downloads", dest_dir=bin_directory
    )


@pytest.fixture(scope="session")
def bin_directory_to_os_path(
    os_path_environment, bin_directory, virtctl_binary, oc_binary
):
    LOGGER.info(f"Adding {bin_directory} to $PATH")
    os.environ["PATH"] = f"{bin_directory}:{os_path_environment}"


@pytest.fixture(autouse=True)
@pytest.mark.early(order=0)
def autouse_fixtures(
    leftovers_cleanup,  # Must be called first to avoid delete created resources.
    bin_directory_to_os_path,
    cluster_info,
    term_handler_scope_function,
    term_handler_scope_class,
    term_handler_scope_module,
    term_handler_scope_session,
    junitxml_polarion,
    admin_client,
    cluster_sanity_scope_session,
    cluster_sanity_scope_module,
    generated_ssh_key_for_vm_access,
):
    """call all autouse fixtures"""


@pytest.fixture(scope="session")
def ssh_key_tmpdir_scope_session(tmpdir_factory):
    yield tmpdir_factory.mktemp("vm-ssh-key-folder")


@pytest.fixture(scope="session")
def generated_ssh_key_for_vm_access(ssh_key_tmpdir_scope_session):
    key_generated = paramiko.RSAKey.generate(bits=2048)
    vm_ssh_key_file = os.path.join(ssh_key_tmpdir_scope_session, "vm_ssh_key.key")
    os.environ[CNV_VM_SSH_KEY_PATH] = vm_ssh_key_file
    key_generated.write_private_key_file(filename=vm_ssh_key_file)
    yield
    if os.path.isfile(vm_ssh_key_file):
        os.unlink(vm_ssh_key_file)
    del os.environ[CNV_VM_SSH_KEY_PATH]


@pytest.fixture(scope="session")
def skip_on_ocp_upgrade(pytestconfig):
    if pytestconfig.option.upgrade == "ocp":
        pytest.skip("This test is not supported for OCP upgrade")


@pytest.fixture(scope="session")
def rhel9_http_image_url():
    return get_http_image_url(
        image_directory=Images.Rhel.DIR, image_name=Images.Rhel.RHEL9_0_IMG
    )


@pytest.fixture(scope="session")
def storage_class_for_snapshot(admin_client):
    available_storage_classes = py_config["storage_class_matrix"]
    sc_for_snapshot = None
    sc_names = []
    for sc in available_storage_classes:
        sc_name = [*sc][0]
        if is_snapshot_supported_by_sc(sc_name=sc_name, client=admin_client):
            sc_for_snapshot = sc_name
            LOGGER.info(f"Storage class for snapshot: {sc_for_snapshot}")
            break
        sc_names.append(sc_name)
    if not sc_for_snapshot:
        LOGGER.warning(f"No Storage class among {sc_names} supports snapshots")
    yield sc_for_snapshot


@pytest.fixture(scope="session")
def skip_if_no_storage_class_for_snapshot(storage_class_for_snapshot):
    if not storage_class_for_snapshot:
        sc_names = [[*sc][0] for sc in py_config["storage_class_matrix"]]
        pytest.skip(
            f"There's no Storage Class among {sc_names} that supports snapshots, skipping the test"
        )


@pytest.fixture()
def audit_logs():
    """Get audit logs names"""
    output = subprocess.getoutput(
        f"{OC_ADM_LOGS_COMMAND} --role=master {AUDIT_LOGS_PATH} | grep audit"
    ).splitlines()
    nodes_logs = defaultdict(list)
    for line in output:
        try:
            node, log = line.split()
            nodes_logs[node].append(log)
        # When failing to get node log, for example "error trying to reach service: ... : connect: connection refused"
        except ValueError:
            LOGGER.error(f"Fail to get log: {line}")

    return nodes_logs


@pytest.fixture()
def alert_not_firing(request, prometheus):
    alert = request.param
    if prometheus.get_alert(alert):
        pytest.xfail(
            f"Alert {alert} should not be in Firing or in Pending state on a cluster before running test"
        )
    return alert


@pytest.fixture(scope="session")
def installing_cnv(pytestconfig):
    return pytestconfig.option.install


@pytest.fixture(scope="session")
def is_production_source(cnv_source):
    return cnv_source == "production"


@pytest.fixture(scope="session")
def cnv_source(pytestconfig):
    return pytestconfig.option.cnv_source or "osbs"


@pytest.fixture(scope="session")
def fips_enabled_cluster(workers_utility_pods):
    """
    Check if FIPS is enabled on cluster
    """
    for pod in workers_utility_pods:
        # command output: 0 == fips disabled
        #                 1 == fips enabled
        cluster_fips_status = pod.execute(
            ["bash", "-c", "cat /proc/sys/crypto/fips_enabled"]
        ).strip()
        if int(cluster_fips_status) == 1:
            return True
    return False


@pytest.fixture(scope="class")
def instance_type_for_test_scope_class(namespace, common_instance_type_param_dict):
    instance_type_param_dict = copy.deepcopy(common_instance_type_param_dict)
    instance_type_param_dict["namespace"] = namespace.name
    return cluster_resource(VirtualMachineInstanceTypeForTest)(
        **instance_type_param_dict
    )


@pytest.fixture(scope="class")
def common_instance_type_param_dict(request):
    return {
        "name": request.param["name"],
        "cpu_cores": request.param.get("cpu_cores"),
        "memory_requests": request.param.get("memory_requests"),
        "dedicated_cpu_placement": request.param.get("dedicated_cpu_placement"),
        "cpu_model": request.param.get("cpu_model"),
        "cpu_isolate_emulator_thread": request.param.get("cpu_isolate_emulator_thread"),
        "cpu_numa": request.param.get("cpu_numa"),
        "cpu_realtime": request.param.get("cpu_realtime"),
        "gpus_list": request.param.get("gpus_list"),
        "host_devices_list": request.param.get("host_devices_list"),
        "io_thread_policy": request.param.get("io_thread_policy"),
        "memory_huge_pages": request.param.get("memory_huge_pages"),
    }


@pytest.fixture(scope="class")
def vm_preference_for_test(namespace, common_vm_preference_param_dict):
    vm_preference_param_dict = copy.deepcopy(common_vm_preference_param_dict)
    vm_preference_param_dict["namespace"] = namespace.name
    return cluster_resource(VirtualMachinePreferenceForTest)(**vm_preference_param_dict)


@pytest.fixture(scope="class")
def common_vm_preference_param_dict(request):
    return {
        "name": request.param["name"],
        "client": request.param.get("client"),
        "teardown": request.param.get("teardown", True),
        "yaml_file": request.param.get("yaml_file"),
        "clock_timezone": request.param.get("clock_timezone"),
        "clock_utc_seconds_offset": request.param.get("clock_utc_seconds_offset"),
        "clock_preferred_timer": request.param.get("clock_preferred_timer"),
        "cpu_topology": request.param.get("cpu_topology"),
        "devices": request.param.get("devices"),
        "features": request.param.get("features"),
        "firmware": request.param.get("firmware"),
        "machine": request.param.get("machine"),
    }


@pytest.fixture(scope="session")
def nightly_art_image_url(openshift_current_version, generated_pulled_secret):
    ocp_version = packaging.version.parse(
        version=openshift_current_version.split("-")[0]
    )
    nightly_image = f"{NIGHTLY_ART_IMAGE}-{ocp_version.major}.{ocp_version.minor}"

    LOGGER.info(f"Checking image {nightly_image} information.")
    command_success, out, err = run_command(
        command=[
            "oc",
            "image",
            "info",
            nightly_image,
            f"--registry-config={generated_pulled_secret}",
            f"--{ICSP_FILTER_BY_OS_LINUX_AMD64}",
        ],
        verify_stderr=False,
    )
    assert (
        command_success
    ), f"Could not find the nightly art operators image. out: {out}. err: {err}"

    return nightly_image


@pytest.fixture(scope="module")
def disabled_default_sources_in_operatorhub_scope_module(admin_client):
    with disable_default_sources_in_operatorhub(admin_client=admin_client):
        yield


@pytest.fixture(scope="session")
def eus_target_cnv_version(is_eus_upgrade, cnv_current_version):
    if is_eus_upgrade:
        cnv_current_version = Version(version=cnv_current_version)
        minor = cnv_current_version.minor
        # EUS-to-EUS updates are only viable between even-numbered minor versions, exit if non-eus version
        if minor % 2:
            exit_pytest_execution(
                message=f"EUS upgrade can not be performed from non-eus version: {cnv_current_version}",
                return_code=EUS_ERROR_CODE,
            )
        return Version(version=f"v{cnv_current_version.major}.{minor + 2}.0")


@pytest.fixture()
def eus_created_target_hco_csv(
    admin_client, hco_namespace, eus_hco_target_version, is_eus_upgrade
):
    if is_eus_upgrade:
        return get_csv_by_name(
            csv_name=eus_hco_target_version,
            admin_client=admin_client,
            namespace=hco_namespace.name,
        )


@pytest.fixture(scope="session")
def is_disconnected_cluster():
    # To enable disconnected_cluster pass --tc=disconnected_cluster:True to pytest commandline.
    return py_config.get("disconnected_cluster")


@pytest.fixture(scope="session")
def skip_on_cnv_upgrade(pytestconfig):
    if pytestconfig.option.upgrade == "cnv":
        pytest.skip("This test is not supported for CNV upgrade")
