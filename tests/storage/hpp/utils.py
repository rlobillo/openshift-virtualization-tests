"""
Utilities for Hostpath Provisioner CSI Custom Resource permutations tests
"""

import logging
from contextlib import contextmanager

from ocp_resources.daemonset import DaemonSet
from ocp_resources.persistent_volume_claim import PersistentVolumeClaim
from ocp_resources.pod import Pod
from ocp_resources.utils import TimeoutSampler
from ocp_utilities.infra import cluster_resource
from pytest_testconfig import py_config

from tests.storage.utils import check_disk_count_in_vm
from utilities.constants import (
    HOSTPATH_PROVISIONER_CSI,
    HOSTPATH_PROVISIONER_OPERATOR,
    HPP_POOL,
    TIMEOUT_1MIN,
    TIMEOUT_2MIN,
    TIMEOUT_5MIN,
    Images,
)
from utilities.infra import ExecCommandOnPod, get_http_image_url, get_pod_by_name_prefix
from utilities.storage import create_dv


LOGGER = logging.getLogger(__name__)


def wait_for_desired_hpp_pods_running(hpp_daemonset, number_of_pods):
    LOGGER.info(f"Wait for {number_of_pods} hpp pods to be running")
    for sample in TimeoutSampler(
        wait_timeout=TIMEOUT_2MIN,
        sleep=1,
        func=lambda: hpp_daemonset.instance.status.desiredNumberScheduled
        == number_of_pods,
    ):
        if sample:
            hpp_daemonset.wait_until_deployed()
            break


def wait_for_hpp_csi_pods_to_be_running(hco_namespace, schedulable_nodes):
    hpp_csi_daemonset = DaemonSet(
        name=HOSTPATH_PROVISIONER_CSI,
        namespace=hco_namespace.name,
    )
    wait_for_desired_hpp_pods_running(
        hpp_daemonset=hpp_csi_daemonset, number_of_pods=len(schedulable_nodes)
    )


def wait_for_hpp_pods(client, pod_prefix):
    return TimeoutSampler(
        wait_timeout=TIMEOUT_2MIN,
        sleep=3,
        func=get_pod_by_name_prefix,
        dyn_client=client,
        namespace=py_config["hco_namespace"],
        pod_prefix=f"{pod_prefix}-",
        get_all=True,
    )


def wait_for_hpp_csi_pods_to_be_deleted(client, pod_prefix):
    LOGGER.info(f"Wait for all {pod_prefix} pods to be deleted")
    for hpp_pods in wait_for_hpp_pods(client=client, pod_prefix=pod_prefix):
        if not hpp_pods:
            break


def wait_for_hpp_operator_running(client):
    LOGGER.info(f"Wait for {HOSTPATH_PROVISIONER_OPERATOR} pod to be Running")
    for hpp_operator_pod in wait_for_hpp_pods(
        client=client, pod_prefix=HOSTPATH_PROVISIONER_OPERATOR
    ):
        if hpp_operator_pod:
            hpp_operator_pod[0].wait_for_status(
                status=Pod.Status.RUNNING, timeout=TIMEOUT_1MIN
            )
            break


def wait_for_hpp_pool_pods_to_be_running(client, schedulable_nodes):
    LOGGER.info(f"Wait for {HPP_POOL} pods to be Running")
    for hpp_pool_pods in wait_for_hpp_pods(client=client, pod_prefix=HPP_POOL):
        if len(hpp_pool_pods) == len(schedulable_nodes):
            for pod in hpp_pool_pods:
                pod.wait_for_status(status=pod.Status.RUNNING, timeout=TIMEOUT_2MIN)
            break


def get_pvc_by_name_prefix(dyn_client, pvc_prefix, namespace):
    """
    Args:
        dyn_client (DynamicClient): OCP Client to use.
        pvc_prefix (str): str
        namespace (str): Namespace name.

    Returns:
         A list of all matching PVCs (empty list if no PVCs found)
    """
    return [
        pvc
        for pvc in cluster_resource(PersistentVolumeClaim).get(
            dyn_client=dyn_client, namespace=namespace
        )
        if pvc.name.startswith(pvc_prefix)
    ]


def verify_hpp_pool_pvcs_are_bound(client, schedulable_nodes, hco_namespace):
    LOGGER.info(f"Wait for {HPP_POOL} PVCs to be Bound")
    pvcs = get_pvc_by_name_prefix(
        dyn_client=client, pvc_prefix=HPP_POOL, namespace=hco_namespace.name
    )
    num_of_pvcs = len(pvcs)
    num_of_schedulable_nodes = len(schedulable_nodes)
    assert num_of_pvcs == num_of_schedulable_nodes, (
        f"There are {num_of_pvcs} {HPP_POOL} PVCs, but expected to be {num_of_schedulable_nodes}."
        f"Existing PVC: {[pvc.name for pvc in pvcs]}"
    )
    for pvc in pvcs:
        pvc.wait_for_status(status=pvc.Status.BOUND, timeout=TIMEOUT_5MIN)


def delete_hpp_pool_pvcs(client, hco_namespace):
    LOGGER.info(f"Wait for {HPP_POOL} PVCs to be Deleted")
    pvcs = get_pvc_by_name_prefix(
        dyn_client=client, pvc_prefix=HPP_POOL, namespace=hco_namespace.name
    )
    [pvc.delete() for pvc in pvcs]
    [pvc.wait_deleted() for pvc in pvcs]


def get_utility_pod_on_specific_node(admin_client, node):
    return [
        pod
        for pod in Pod.get(
            dyn_client=admin_client, label_selector="cnv-test=utility-pods-for-hpp-test"
        )
        if pod.node.name == node
    ][0]


def wait_for_utility_pod_to_be_running(admin_client, node):
    LOGGER.info(f"Wait for utility pod from node {node} to be running")
    for util_pod in TimeoutSampler(
        wait_timeout=TIMEOUT_2MIN,
        sleep=3,
        func=get_utility_pod_on_specific_node,
        admin_client=admin_client,
        node=node,
    ):
        if util_pod:
            util_pod.wait_for_status(
                status=util_pod.Status.RUNNING, timeout=TIMEOUT_2MIN
            )
            break


def refresh_utility_pod(admin_client, node):
    # Utility pods were created at the beginning of the test call,
    # but DV's PVC wasn't created yet at that moment,
    # so we need to delete the utility pod and wait till it'll be recreated.
    get_utility_pod_on_specific_node(admin_client=admin_client, node=node).delete(
        wait=True
    )
    wait_for_utility_pod_to_be_running(admin_client=admin_client, node=node)
    return get_utility_pod_on_specific_node(admin_client=admin_client, node=node)


def assert_image_location_via_node_utility_pod(dv, storage_pool_path, admin_client):
    node = dv.pvc.selected_node
    utility_pod = refresh_utility_pod(admin_client=admin_client, node=node)
    path = f"{storage_pool_path}/csi/{dv.pvc.instance.spec.volumeName}"
    LOGGER.info(f"Verify disk.img is at /var/{path}")
    out = ExecCommandOnPod(utility_pods=[utility_pod], node=node).exec(
        command=f"ls /var/{path}/"
    )
    assert out == "disk.img", f"Expected to get disk.img, but got: {out}"


def is_hpp_cr_with_pvc_template(hpp_custom_resource):
    if hpp_custom_resource.instance.spec.pathConfig:
        return False
    return any(
        [
            template.get("pvcTemplate")
            for template in hpp_custom_resource.instance.spec.storagePools
        ]
    )


def verify_hpp_cr_installed_successfully(
    hco_namespace, schedulable_nodes, client, hpp_custom_resource
):
    wait_for_hpp_csi_pods_to_be_running(
        hco_namespace=hco_namespace, schedulable_nodes=schedulable_nodes
    )
    if is_hpp_cr_with_pvc_template(hpp_custom_resource=hpp_custom_resource):
        wait_for_hpp_pool_pods_to_be_running(
            client=client, schedulable_nodes=schedulable_nodes
        )
        # Check there are as many 'hpp-pool-' PVCs as schedulable_nodes, and they are Bound
        verify_hpp_pool_pvcs_are_bound(
            client=client,
            schedulable_nodes=schedulable_nodes,
            hco_namespace=hco_namespace,
        )


def verify_hpp_cr_deleted_successfully(
    hco_namespace, schedulable_nodes, client, is_hpp_cr_with_pvc_template=False
):
    wait_for_hpp_csi_pods_to_be_deleted(
        client=client, pod_prefix=HOSTPATH_PROVISIONER_CSI
    )
    if is_hpp_cr_with_pvc_template:
        wait_for_hpp_csi_pods_to_be_deleted(client=client, pod_prefix=HPP_POOL)
        wait_for_hpp_operator_running(client=client)
        # Check PVCs are still there and Bound
        verify_hpp_pool_pvcs_are_bound(
            client=client,
            schedulable_nodes=schedulable_nodes,
            hco_namespace=hco_namespace,
        )
        # Delete PVCs to cleanup the cluster
        delete_hpp_pool_pvcs(client=client, hco_namespace=hco_namespace)


def check_disk_count_in_vm_and_image_location(
    vm, dv, hpp_csi_storage_class, admin_client
):
    check_disk_count_in_vm(vm=vm)
    assert_image_location_via_node_utility_pod(
        dv=dv,
        admin_client=admin_client,
        storage_pool_path=hpp_csi_storage_class.instance.parameters.storagePool,
    )


@contextmanager
def cirros_dv_on_hpp(dv_name, storage_class, namespace):
    with create_dv(
        dv_name=dv_name,
        namespace=namespace.name,
        url=get_http_image_url(
            image_directory=Images.Cirros.DIR, image_name=Images.Cirros.QCOW2_IMG
        ),
        size=Images.Cirros.DEFAULT_DV_SIZE,
        storage_class=storage_class,
    ) as dv:
        yield dv
