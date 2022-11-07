import multiprocessing
import random

import pytest
from ocp_resources.service import Service

from tests.chaos.utils import create_nginx_monitoring_process, terminate_process
from utilities.constants import PORT_80, TIMEOUT_5SEC
from utilities.infra import ExecCommandOnPod, cluster_resource, label_nodes
from utilities.virt import VirtualMachineForTests, fedora_vm_body, running_vm


@pytest.fixture()
def chaos_worker_background_process(
    request, workers_utility_pods, workers, vm_node_with_chaos_label
):

    timeout = request.param["max_duration"]
    command = request.param["background_command"]

    background_process = multiprocessing.Process(
        target=lambda: ExecCommandOnPod(
            utility_pods=workers_utility_pods, node=vm_node_with_chaos_label[0]
        ).exec(command=command, chroot_host=False, timeout=timeout + TIMEOUT_5SEC),
    )
    yield background_process
    terminate_process(process=background_process)


@pytest.fixture()
def nginx_monitoring_process(
    request,
    masters,
    masters_utility_pods,
    vm_with_nginx_service,
):
    curl_timeout = request.param["curl_timeout"]
    sampling_duration = request.param["sampling_duration"]
    sampling_interval = request.param["sampling_interval"]
    nginx_monitoring_process = create_nginx_monitoring_process(
        url=f"{vm_with_nginx_service.custom_service.instance.spec.clusterIPs[0]}:{PORT_80}",
        curl_timeout=curl_timeout,
        sampling_duration=sampling_duration,
        sampling_interval=sampling_interval,
        utility_pods=masters_utility_pods,
        master_host_node=random.choice(masters),
    )
    yield nginx_monitoring_process
    terminate_process(process=nginx_monitoring_process)


@pytest.fixture()
def vm_with_nginx_service(chaos_namespace, admin_client):
    name = "nginx"
    with cluster_resource(VirtualMachineForTests)(
        namespace=chaos_namespace.name,
        name=name,
        body=fedora_vm_body(name=name),
        client=admin_client,
    ) as vm:
        running_vm(vm=vm, check_ssh_connectivity=False)
        vm.custom_service_enable(
            service_name=name, port=PORT_80, service_type=Service.Type.CLUSTER_IP
        )
        yield vm


@pytest.fixture()
def vm_node_with_chaos_label(vm_with_nginx_service):
    yield from list(
        label_nodes(nodes=[vm_with_nginx_service.vmi.node], labels={"chaos": "true"})
    )
