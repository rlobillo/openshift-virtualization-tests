import logging
import os
import random
import shutil
import subprocess
import sys

import pytest
from git import Repo
from ocp_resources.cluster_role import ClusterRole
from ocp_resources.cluster_role_binding import ClusterRoleBinding
from ocp_resources.service_account import ServiceAccount
from ocp_resources.utils import TimeoutSampler
from pytest_testconfig import py_config

from tests.chaos.constants import (
    CHAOS_ENGINE_FILE_PATH,
    CHAOS_NAMESPACE,
    KRKN_CONFIG_PATH,
    KRKN_REPO,
    LITMUS_NAMESPACE,
    LITMUS_SERVICE_ACCOUNT,
    VM_LABEL,
)
from tests.chaos.utils.chaos_engine import (
    AppInfo,
    ChaosEngineFromFile,
    CmdProbe,
    EnvComponent,
    Experiment,
    K8SProbe,
)
from tests.chaos.utils.krkn_process import KrknProcess
from utilities.constants import (
    KUBEMACPOOL_MAC_CONTROLLER_MANAGER,
    TIMEOUT_1MIN,
    TIMEOUT_3MIN,
    TIMEOUT_5SEC,
    TIMEOUT_10MIN,
    Images,
)
from utilities.infra import (
    ExecCommandOnPod,
    cluster_resource,
    create_ns,
    get_pod_by_name_prefix,
    wait_for_node_status,
)
from utilities.virt import CIRROS_IMAGE, VirtualMachineForTests, running_vm


LOGGER = logging.getLogger(__name__)


@pytest.fixture()
def chaos_namespace():
    yield from create_ns(name=CHAOS_NAMESPACE)


@pytest.fixture()
def litmus_namespace():
    yield from create_ns(name=LITMUS_NAMESPACE)


@pytest.fixture()
def litmus_service_account(litmus_namespace):
    with cluster_resource(ServiceAccount)(
        name=LITMUS_SERVICE_ACCOUNT, namespace=litmus_namespace.name
    ) as sa:
        yield sa


@pytest.fixture()
def litmus_cluster_role(litmus_service_account):
    with cluster_resource(ClusterRole)(
        name=litmus_service_account.name,
        api_groups=[
            "",
            "apps",
            "batch",
            "extensions",
            "litmuschaos.io",
            "openebs.io",
            "storage.k8s.io",
            "kubevirt.io",
        ],
        permissions_to_resources=[
            "nodes",
            "chaosengines",
            "chaosexperiments",
            "chaosresults",
            "configmaps",
            "cstorpools",
            "cstorvolumereplicas",
            "daemonsets",
            "deployments",
            "events",
            "jobs",
            "persistentvolumeclaims",
            "persistentvolumes",
            "pods",
            "pods/eviction",
            "pods/exec",
            "pods/log",
            "replicasets",
            "secrets",
            "services",
            "statefulsets",
            "storageclasses",
            "virtualmachineinstances",
        ],
        verbs=["create", "delete", "get", "list", "patch", "update"],
    ) as cluster_role:
        yield cluster_role


@pytest.fixture()
def litmus_cluster_role_binding(
    litmus_namespace, litmus_service_account, litmus_cluster_role
):
    with cluster_resource(ClusterRoleBinding)(
        name=litmus_cluster_role.name,
        cluster_role=litmus_cluster_role.name,
        subjects=[
            {
                "kind": "ServiceAccount",
                "name": litmus_service_account.name,
                "namespace": litmus_namespace.name,
            }
        ],
    ) as cluster_role_binding:
        yield cluster_role_binding


@pytest.fixture()
def vm_cirros_chaos(admin_client, chaos_namespace):
    with cluster_resource(VirtualMachineForTests)(
        client=admin_client,
        name="vm-chaos",
        namespace=chaos_namespace.name,
        image=CIRROS_IMAGE,
        memory_requests=Images.Cirros.DEFAULT_MEMORY_SIZE,
        additional_labels=VM_LABEL,
        eviction=True,
    ) as vm:
        running_vm(vm=vm, wait_for_interfaces=False, check_ssh_connectivity=False)
        yield vm


@pytest.fixture()
def chaos_engine_from_yaml(request, litmus_cluster_role_binding):
    experiment_name = request.param["experiment_name"]
    app_info_data = request.param.get("app_info")
    components_data = request.param["components"]

    k8s_probes = create_k8s_probes(probes_data=request.param.get("k8s_probes"))
    cmd_probes = create_cmd_probes(probes_data=request.param.get("cmd_probes"))

    app_info = None
    if app_info_data:
        app_info = AppInfo(
            namespace=app_info_data["namespace"],
            label=app_info_data["label"],
            kind=app_info_data["kind"],
        )

    components = []
    for component in components_data:
        if component["name"] == "TARGET_NODE" and component["value"] == "vm_node":
            vm = request.getfixturevalue("vm_cirros_chaos")
            components.append(EnvComponent(name="TARGET_NODE", value=vm.vmi.node.name))
        else:
            components.append(
                EnvComponent(name=component["name"], value=component["value"])
            )

    experiment = Experiment(
        name=experiment_name,
        probes=k8s_probes + cmd_probes,
        env_components=components,
    )
    chaos_engine = ChaosEngineFromFile(app_info=app_info, experiments=[experiment])
    chaos_engine.create_yaml()
    yield chaos_engine
    os.remove(CHAOS_ENGINE_FILE_PATH)
    chaos_engine.clean_up()


def create_k8s_probes(probes_data):
    if probes_data:
        return [
            K8SProbe(
                name=probe["name"],
                mode=probe["mode"],
                probe_timeout=probe["probe_timeout"],
                interval=probe["interval"],
                retries=probe["retries"],
                group=probe.get("group"),
                version=probe.get("version"),
                resource=probe.get("resource"),
                namespace=probe.get("namespace"),
                operation=probe.get("operation"),
                label_selector=probe.get("label_selector"),
                field_selector=probe.get("field_selector"),
                data=probe.get("data"),
            )
            for probe in probes_data
        ]
    return []


def create_cmd_probes(probes_data):
    if probes_data:
        return [
            CmdProbe(
                name=probe["name"],
                mode=probe["mode"],
                probe_timeout=probe["probe_timeout"],
                interval=probe["interval"],
                retries=probe["retries"],
                command=probe["command"],
                comparator_type=probe["comparator_type"],
                comparator_criteria=probe["comparator_criteria"],
                comparator_value=probe["comparator_value"],
            )
            for probe in probes_data
        ]
    return []


@pytest.fixture(scope="session")
def cloned_krkn_repo():
    repo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "krkn")
    repo = Repo.clone_from(url=KRKN_REPO, to_path=repo_path, branch="main")
    yield repo
    shutil.rmtree(path=repo_path, ignore_errors=True)


@pytest.fixture(scope="session")
def installed_krkn_dependencies(cloned_krkn_repo):
    subprocess.check_call(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "-r",
            os.path.join(cloned_krkn_repo.working_dir, "requirements.txt"),
        ]
    )
    yield


@pytest.fixture()
def krkn_process(cloned_krkn_repo, installed_krkn_dependencies):
    krkn_process = KrknProcess(repo_path=cloned_krkn_repo.working_dir)
    krkn_process.run()
    yield krkn_process
    os.remove(f"{KRKN_CONFIG_PATH}")


@pytest.fixture()
def running_chaos_engine(chaos_engine_from_yaml, krkn_process):
    chaos_engine_from_yaml.wait()
    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_1MIN,
        sleep=TIMEOUT_5SEC,
        func=lambda: chaos_engine_from_yaml.experiments_status[
            chaos_engine_from_yaml.experiments[0].name
        ]["status"],
    )
    for sample in samples:
        if sample and sample == chaos_engine_from_yaml.Status.RUNNING:
            return chaos_engine_from_yaml


@pytest.fixture()
def kmp_manager_nodes(admin_client):
    yield [
        pod.node
        for pod in get_pod_by_name_prefix(
            dyn_client=admin_client,
            pod_prefix=KUBEMACPOOL_MAC_CONTROLLER_MANAGER,
            namespace=py_config["hco_namespace"],
            get_all=True,
        )
    ]


@pytest.fixture()
def rebooted_master_node(request, admin_client, masters, kmp_manager_nodes):
    master_node_to_reboot = request.param["master_node_to_reboot"]

    if master_node_to_reboot == "node_with_kmp_manager":
        yield random.choice(seq=kmp_manager_nodes)
    else:
        yield random.choice(
            seq=[
                node
                for node in masters
                if node.name not in [node.name for node in kmp_manager_nodes]
            ]
        )


@pytest.fixture()
def rebooting_master_node(
    rebooted_master_node,
    masters_utility_pods,
):
    LOGGER.info(f"Rebooting master node {rebooted_master_node.name}...")
    ExecCommandOnPod(utility_pods=masters_utility_pods, node=rebooted_master_node).exec(
        command="shutdown -r", ignore_rc=True
    )
    wait_for_node_status(
        node=rebooted_master_node, status=False, wait_timeout=TIMEOUT_3MIN
    )
    yield rebooted_master_node
    wait_for_node_status(node=rebooted_master_node, wait_timeout=TIMEOUT_10MIN)
