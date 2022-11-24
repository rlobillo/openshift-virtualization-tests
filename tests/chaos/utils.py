import http
import json
import logging
import multiprocessing
import random
import time
from contextlib import contextmanager
from datetime import datetime

from ocp_resources.node import Node
from ocp_resources.service import Service
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler, TimeoutWatch
from ocp_utilities.data_collector import write_to_file
from ocp_utilities.infra import cluster_resource
from pytest_testconfig import py_config

from utilities.constants import (
    DEFAULT_HCO_CONDITIONS,
    PORT_80,
    TIMEOUT_1MIN,
    TIMEOUT_5SEC,
    TIMEOUT_10SEC,
    TIMEOUT_30MIN,
)
from utilities.infra import (
    ExecCommandOnPod,
    get_daemonsets,
    get_deployments,
    get_hco_mismatch_statuses,
    get_hyperconverged_resource,
    get_pod_by_name_prefix,
    get_pods,
)
from utilities.virt import VirtualMachineForTests, fedora_vm_body, running_vm


LOGGER = logging.getLogger(__name__)


def create_pod_deleting_process(
    dyn_client,
    pod_prefix,
    namespace_name,
    ratio,
    interval=TIMEOUT_5SEC,
    max_duration=TIMEOUT_1MIN,
):
    """
    Creates a process that, when started,
    continuously deletes pods for a certain amount of time or until the process is stopped.

    Args:
        dyn_client (DynamicClient)
        pod_prefix (str): Pod name prefix used to find the pods to be deleted.
        namespace_name (str): Name of the namespace were the pods to be deleted live.
        ratio (float): Percentage of pods to be deleted (expressed as a fraction between 0 and 1).
        interval (int): Interval that determines how often the pods will be deleted.
        max_duration (int): Maximum time that the process will be running.

    Returns:
        multiprocessing.Process: Process that continuously deletes pods.

    Example:
        pod_deleting_process = create_pod_deleting_process(
            dyn_client=admin_client, pod_prefix="apiserver",
            namespace_name="openshift-apiserver", ratio=0.5, interval=5, max_duration=180
        )
        pod_deleting_process.start()
        ...
        pod_deleting_process.terminate()
    """

    def _choose_surviving_pods(dyn_client, pod_prefix, namespace_name, ratio):
        initial_pods = get_pod_by_name_prefix(
            dyn_client=dyn_client,
            pod_prefix=pod_prefix,
            namespace=namespace_name,
            get_all=True,
        )
        number_of_deleted_pods = round(number=ratio * len(initial_pods))
        LOGGER.info(
            f"Number of pods to delete: {number_of_deleted_pods} out of {len(initial_pods)}."
        )
        surviving_pods = [
            pod
            for pod in random.sample(
                population=initial_pods, k=len(initial_pods) - number_of_deleted_pods
            )
        ]
        LOGGER.info(f"Surviving pods: {[pod.name for pod in surviving_pods]}")

        return surviving_pods

    def _delete_pods(dyn_client, pod_prefix, namespace_name, surviving_pods):
        deleted_pods = get_pod_by_name_prefix(
            dyn_client=dyn_client,
            pod_prefix=pod_prefix,
            namespace=namespace_name,
            get_all=True,
        )
        for pod in deleted_pods:
            if pod.name not in [surviving_pod.name for surviving_pod in surviving_pods]:
                # Set the log level to ERROR to avoid cluttering the console with the logs resulting from pod deletion
                with resource_log_level_error(resource=pod) as _pod:
                    _pod.delete()

    def _delete_pods_continuously(
        dyn_client, pod_prefix, namespace_name, ratio, interval, max_duration
    ):
        surviving_pods = _choose_surviving_pods(
            dyn_client=dyn_client,
            pod_prefix=pod_prefix,
            namespace_name=namespace_name,
            ratio=ratio,
        )

        try:
            for _ in TimeoutSampler(
                wait_timeout=max_duration,
                sleep=interval,
                func=_delete_pods,
                dyn_client=dyn_client,
                pod_prefix=pod_prefix,
                namespace_name=namespace_name,
                surviving_pods=surviving_pods,
            ):
                pass
        except TimeoutExpiredError:
            LOGGER.info("Pod deleting process finished.")

    return multiprocessing.Process(
        name="pod_delete",
        target=_delete_pods_continuously,
        args=(
            dyn_client,
            pod_prefix,
            namespace_name,
            ratio,
            interval,
            max_duration,
        ),
    )


def create_nginx_monitoring_process(
    url,
    curl_timeout,
    sampling_duration,
    sampling_interval,
    utility_pods,
    master_host_node,
):
    """
    Creates a process that, when started,
    Continuously queries the HTTP server that runs on the VM. Runs for the duration defined
    in 'sampling_duration' or until interrupted.

    Args:
        url (str): The url of the http server.
        curl_timeout (int): timeout in seconds for curl connect-timeout parameter.
        sampling_duration (str): The amount of time during which sampling will take place.
        sampling_interval (int): Interval that determines how often the http server will be queried.

    Returns:
        multiprocessing.Process: Process that continuously query the http server.
    """

    def _monitor_nginx_server(
        _url,
        _curl_timeout,
        _sampling_duration,
        _sampling_interval,
        _utility_pods,
        _master_host_node,
    ):
        timeout_watch = TimeoutWatch(timeout=_sampling_duration)
        while timeout_watch.remaining_time() > 0:
            http_result = ExecCommandOnPod(
                utility_pods=_utility_pods, node=_master_host_node
            ).exec(
                command=f"curl -s --connect-timeout {_curl_timeout} -w '%{{http_code}}'  {_url}  -o /dev/null"
            )
            if http.HTTPStatus.OK != int(http_result):
                raise Exception(f"Wrong status code ({http_result}) from server.")
            time.sleep(_sampling_interval)
        LOGGER.info("HTTP querying finished successfully ")

    return multiprocessing.Process(
        name="nginx_monitoring",
        target=_monitor_nginx_server,
        args=(
            url,
            curl_timeout,
            sampling_duration,
            sampling_interval,
            utility_pods,
            master_host_node,
        ),
    )


def get_pods_status(admin_client, namespaces):
    pods_status = {"pod_status": {}}
    for namespace in namespaces:
        pods = get_pods(dyn_client=admin_client, namespace=namespace)
        pods_status["pod_status"][namespace.name] = {}
        for pod in pods:
            # Set the log level to ERROR to avoid cluttering the console
            with resource_log_level_error(resource=pod) as _pod:
                pods_status["pod_status"][namespace.name][_pod.name] = _pod.status

    return pods_status


def get_deployment_replicas(admin_client, namespaces):
    deployments_replicas = {"deployment_replicas": {}}
    for namespace in namespaces:
        deployments = get_deployments(
            admin_client=admin_client, namespace=namespace.name
        )
        deployments_replicas["deployment_replicas"][namespace.name] = {}
        for deployment in deployments:
            # Set the log level to ERROR to avoid cluttering the console
            with resource_log_level_error(resource=deployment) as _deployment:
                deployment_instance = _deployment.instance
                deployments_replicas["deployment_replicas"][namespace.name][
                    _deployment.name
                ] = {
                    "desired": deployment_instance.spec.replicas,
                    "available": deployment_instance.status.availableReplicas,
                }

    return deployments_replicas


def get_daemonset_replicas(admin_client, namespaces):
    daemonsets_replicas = {"daemonset_replicas": {}}
    for namespace in namespaces:
        daemonsets = get_daemonsets(admin_client=admin_client, namespace=namespace.name)
        daemonsets_replicas["daemonset_replicas"][namespace.name] = {}
        for daemonset in daemonsets:
            # Set the log level to ERROR to avoid cluttering the console
            with resource_log_level_error(resource=daemonset) as _daemonset:
                daemonset_instance = _daemonset.instance
                daemonsets_replicas["daemonset_replicas"][namespace.name][
                    _daemonset.name
                ] = {
                    "desired": daemonset_instance.status.desiredNumberScheduled,
                    "ready": daemonset_instance.status.numberReady,
                }

    return daemonsets_replicas


def get_nodes_status():
    nodes_status = {"nodes": {}}
    for node in Node.get():
        # Set loglevel to ERROR to avoid cluttering with the logs resulting from getting node status
        with resource_log_level_error(resource=node) as _node:
            nodes_status["nodes"][node.name] = (
                "ready" if _node.kubelet_ready else "not ready"
            )

    return nodes_status


def get_hyperconverged_status_conditions(client, hco_namespace):
    hco_instance = get_hyperconverged_resource(
        client=client, hco_ns_name=hco_namespace.name
    ).instance
    hco_status_summary = (
        "OK"
        if not get_hco_mismatch_statuses(
            hco_instance.status.conditions, DEFAULT_HCO_CONDITIONS
        )
        else "NOK"
    )

    return {
        "hco_status": {
            "summary": hco_status_summary,
            "hco_status_conditions": hco_instance.to_dict()["status"]["conditions"],
        }
    }


def collect_cluster_health_info(client, hco_namespace, additional_namespaces):
    namespaces_to_monitor = additional_namespaces + [hco_namespace]
    pods_status = get_pods_status(admin_client=client, namespaces=namespaces_to_monitor)
    deployments_replicas = get_deployment_replicas(
        admin_client=client, namespaces=namespaces_to_monitor
    )
    daemonset_replicas = get_daemonset_replicas(
        admin_client=client, namespaces=namespaces_to_monitor
    )
    nodes_status = get_nodes_status()
    hco_status_conditions = get_hyperconverged_status_conditions(
        client=client, hco_namespace=hco_namespace
    )

    log_content = json.dumps(
        {
            f'{datetime.utcnow().strftime("%Y/%m/%d %H:%M:%S")}': [
                pods_status,
                deployments_replicas,
                daemonset_replicas,
                nodes_status,
                hco_status_conditions,
            ]
        },
        indent=4,
    )

    write_to_file(
        file_name="chaos-monitoring.txt",
        content=f"{log_content}\n",
        base_directory=py_config["data_collector"]["collector_directory"],
        mode="a",
    )


def create_cluster_monitoring_process(
    client,
    hco_namespace,
    additional_namespaces,
    interval=TIMEOUT_10SEC,
    max_duration=TIMEOUT_30MIN,
):
    def _monitor_cluster():
        timeout_watch = TimeoutWatch(timeout=max_duration)
        while timeout_watch.remaining_time() > 0:
            collect_cluster_health_info(
                client=client,
                hco_namespace=hco_namespace,
                additional_namespaces=additional_namespaces,
            )
            time.sleep(interval)

    return multiprocessing.Process(
        name="cluster_monitoring",
        target=_monitor_cluster,
    )


def terminate_process(process):
    if process.is_alive():
        LOGGER.info(f"Terminating process: {process.name}")
        process.kill()


@contextmanager
def resource_log_level_error(resource):
    resource.logger.setLevel(level=logging.ERROR)
    yield resource
    resource.logger.setLevel(level=logging.INFO)


def create_vm_with_nginx_service(
    chaos_namespace, admin_client, node_selector_label=None
):
    name = "nginx"
    with cluster_resource(VirtualMachineForTests)(
        namespace=chaos_namespace.name,
        name=name,
        body=fedora_vm_body(name=name),
        client=admin_client,
        node_selector_labels=node_selector_label,
        eviction=True,
    ) as vm:
        running_vm(vm=vm, check_ssh_connectivity=False)
        vm.custom_service_enable(
            service_name=name, port=PORT_80, service_type=Service.Type.CLUSTER_IP
        )
        LOGGER.info(f"VMI Host Node:{vm.vmi.node.name}")
        yield vm
