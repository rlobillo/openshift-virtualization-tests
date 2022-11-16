# -*- coding: utf-8 -*-

"""
HPP Node Placement test suite
"""
import logging
from contextlib import contextmanager

import pytest
from ocp_resources.datavolume import DataVolume
from ocp_resources.persistent_volume import PersistentVolume
from ocp_resources.persistent_volume_claim import PersistentVolumeClaim
from ocp_resources.resource import ResourceEditor
from ocp_resources.virtual_machine_instance import VirtualMachineInstance
from ocp_utilities.infra import cluster_resource
from openshift.dynamic.exceptions import ResourceNotFoundError

from tests.storage.hpp.utils import wait_for_desired_hpp_pods_running
from tests.storage.utils import check_disk_count_in_vm
from utilities.constants import OS_FLAVOR_CIRROS, TIMEOUT_1MIN, TIMEOUT_5MIN, Images
from utilities.hco import add_labels_to_nodes
from utilities.infra import get_http_image_url
from utilities.virt import VirtualMachineForTests, running_vm


LOGGER = logging.getLogger(__name__)

HPP_KEY = "hpp-key"
HPP_VAL = "hpp-val1"

HCO_NODE_PLACEMENT = {
    "infra": {},
    "workloads": {
        "nodePlacement": {
            "nodeSelector": {HPP_KEY: HPP_VAL},
        }
    },
}

HPP_NODE_PLACEMENT_DICT = {
    "node_selector": {
        "spec": {
            "workload": {
                "nodeSelector": {HPP_KEY: HPP_VAL},
            }
        }
    },
    "affinity": {
        "spec": {
            "workload": {
                "affinity": {
                    "nodeAffinity": {
                        "requiredDuringSchedulingIgnoredDuringExecution": {
                            "nodeSelectorTerms": [
                                {
                                    "matchExpressions": [
                                        {
                                            "key": HPP_KEY,
                                            "operator": "In",
                                            "values": [HPP_VAL],
                                        }
                                    ]
                                }
                            ]
                        }
                    }
                }
            }
        }
    },
    "tolerations": {
        "spec": {
            "workload": {
                "tolerations": [
                    {
                        "effect": "NoExecute",
                        "key": HPP_KEY,
                        "operator": "Exists",
                        "value": HPP_VAL,
                    }
                ]
            }
        }
    },
}

pytestmark = pytest.mark.usefixtures("skip_test_if_no_hpp_sc")


@contextmanager
def update_node_taint(node):
    with ResourceEditor(
        patches={
            node: {
                "spec": {
                    "taints": [
                        {"effect": "NoExecute", "key": HPP_KEY, "value": HPP_VAL}
                    ]
                }
            }
        }
    ):
        yield


@contextmanager
def cirros_vm_on_hpp(
    dv_name,
    vm_name,
    client,
    namespace,
    storage_class,
    node=None,
    wait_for_deletion=True,
):
    dv = cluster_resource(DataVolume)(
        name=dv_name,
        namespace=namespace.name,
        source="http",
        url=get_http_image_url(
            image_directory=Images.Cirros.DIR, image_name=Images.Cirros.QCOW2_IMG
        ),
        storage_class=storage_class,
        size=Images.Cirros.DEFAULT_DV_SIZE,
        api_name="storage",
    )
    dv.to_dict()
    dv_metadata = dv.res["metadata"]
    with cluster_resource(VirtualMachineForTests)(
        client=client,
        name=vm_name,
        namespace=dv_metadata["namespace"],
        os_flavor=OS_FLAVOR_CIRROS,
        memory_requests=Images.Cirros.DEFAULT_MEMORY_SIZE,
        data_volume_template={"metadata": dv_metadata, "spec": dv.res["spec"]},
        node_selector=node,
        running=True,
    ) as vm:
        yield vm
    if wait_for_deletion:
        if vm.vmi.exists:
            vm.vmi.wait_deleted(timeout=TIMEOUT_5MIN)


@pytest.fixture(scope="module")
def update_node_labels(worker_node1):
    worker_resources = add_labels_to_nodes(
        nodes=[
            worker_node1,
        ],
        node_labels={HPP_KEY: "hpp-val"},
    )
    yield
    for worker_resource in worker_resources:
        worker_resource.restore()


@pytest.fixture()
def updated_hpp_with_node_placement(
    worker_node2,
    worker_node3,
    hostpath_provisioner_scope_module,
    request,
    admin_client,
    hpp_daemonset_scope_session,
    schedulable_nodes,
):
    node_placement_type = request.param["type"]
    with ResourceEditor(
        patches={
            hostpath_provisioner_scope_module: HPP_NODE_PLACEMENT_DICT[
                node_placement_type
            ]
        }
    ) as updated_resource:
        if node_placement_type == "tolerations":
            with update_node_taint(node=worker_node2), update_node_taint(
                node=worker_node3
            ):
                # Wait for 1 hpp pod to be running, and for others to be deleted
                wait_for_desired_hpp_pods_running(
                    hpp_daemonset=hpp_daemonset_scope_session, number_of_pods=1
                )
                yield updated_resource
        else:
            # Wait for 1 hpp pod to be running, and for others to be deleted
            wait_for_desired_hpp_pods_running(
                hpp_daemonset=hpp_daemonset_scope_session, number_of_pods=1
            )
            yield updated_resource
    # Wait for hpp pods to be restored
    wait_for_desired_hpp_pods_running(
        hpp_daemonset=hpp_daemonset_scope_session, number_of_pods=len(schedulable_nodes)
    )


@pytest.mark.destructive
@pytest.mark.parametrize(
    ("updated_hpp_with_node_placement", "hyperconverged_with_node_placement"),
    [
        pytest.param(
            {"type": "node_selector"},
            HCO_NODE_PLACEMENT,
            marks=pytest.mark.polarion("CNV-5711"),
        ),
        pytest.param(
            {"type": "affinity"},
            HCO_NODE_PLACEMENT,
            marks=pytest.mark.polarion("CNV-5712"),
        ),
        pytest.param(
            {"type": "tolerations"},
            HCO_NODE_PLACEMENT,
            marks=pytest.mark.polarion("CNV-5713"),
        ),
    ],
    indirect=True,
)
def test_create_dv_on_right_node_with_node_placement(
    worker_node1,
    admin_client,
    namespace,
    update_node_labels,
    updated_hpp_with_node_placement,
    hyperconverged_with_node_placement,
    storage_class_matrix_hpp_matrix__module__,
):
    with cirros_vm_on_hpp(
        dv_name="cirros-dv",
        vm_name="cirros-vm",
        client=admin_client,
        namespace=namespace,
        storage_class=[*storage_class_matrix_hpp_matrix__module__][0],
    ) as vm:
        running_vm(vm=vm, wait_for_interfaces=False)
        # The VM should be created on the node that have the node labels
        assert vm.vmi.node.name == worker_node1.name


@pytest.mark.post_upgrade
@pytest.mark.parametrize(
    ("updated_hpp_with_node_placement"),
    [
        pytest.param(
            {"type": "node_selector"},
            marks=pytest.mark.polarion("CNV-5717"),
        ),
    ],
    indirect=True,
)
def test_create_vm_on_node_without_hpp_pod_and_after_update(
    worker_node2,
    admin_client,
    namespace,
    update_node_labels,
    updated_hpp_with_node_placement,
    storage_class_matrix_hpp_matrix__module__,
):
    with cirros_vm_on_hpp(
        dv_name="dv-5717",
        vm_name="vm-5717",
        client=admin_client,
        namespace=namespace,
        node=worker_node2.name,
        storage_class=[*storage_class_matrix_hpp_matrix__module__][0],
    ) as vm:
        vm.vmi.wait_for_status(
            status=VirtualMachineInstance.Status.PENDING,
            timeout=TIMEOUT_1MIN,
            stop_status=VirtualMachineInstance.Status.RUNNING,
        )
        updated_hpp_with_node_placement.restore()
        vm.vmi.wait_for_status(
            status=VirtualMachineInstance.Status.RUNNING,
            timeout=TIMEOUT_5MIN,
        )


@pytest.mark.post_upgrade
@pytest.mark.polarion("CNV-5601")
def test_vm_with_dv_on_functional_after_configuring_hpp_not_to_work_on_that_same_node(
    hostpath_provisioner_scope_module,
    worker_node2,
    admin_client,
    namespace,
    update_node_labels,
    hpp_daemonset_scope_session,
    schedulable_nodes,
    storage_class_matrix_hpp_matrix__module__,
):
    with cirros_vm_on_hpp(
        dv_name="dv-5601",
        vm_name="vm-5601",
        client=admin_client,
        namespace=namespace,
        node=worker_node2.name,
        storage_class=[*storage_class_matrix_hpp_matrix__module__][0],
    ) as vm:
        running_vm(vm=vm, wait_for_interfaces=False)
        check_disk_count_in_vm(vm=vm)
        with ResourceEditor(
            patches={
                hostpath_provisioner_scope_module: HPP_NODE_PLACEMENT_DICT[
                    "node_selector"
                ]
            }
        ):
            # Wait for 1 hpp pod to be running, and for others to be deleted
            wait_for_desired_hpp_pods_running(
                hpp_daemonset=hpp_daemonset_scope_session, number_of_pods=1
            )
            check_disk_count_in_vm(vm=vm)
    # Wait for hpp pods to be restored
    wait_for_desired_hpp_pods_running(
        hpp_daemonset=hpp_daemonset_scope_session, number_of_pods=len(schedulable_nodes)
    )


@pytest.mark.post_upgrade
@pytest.mark.polarion("CNV-5616")
def test_pv_stay_released_after_deleted_when_no_hpp_pod(
    hostpath_provisioner_scope_module,
    worker_node1,
    worker_node2,
    admin_client,
    namespace,
    update_node_labels,
    hpp_daemonset_scope_session,
    schedulable_nodes,
    storage_class_matrix_hpp_matrix__module__,
):
    dv_name = "dv-5616"
    with cirros_vm_on_hpp(
        dv_name=dv_name,
        vm_name="vm-5616",
        client=admin_client,
        namespace=namespace,
        node=worker_node2.name,
        storage_class=[*storage_class_matrix_hpp_matrix__module__][0],
    ) as vm:
        running_vm(vm=vm, wait_for_interfaces=False)
        pvc_list = list(
            cluster_resource(PersistentVolumeClaim).get(
                dyn_client=admin_client,
                namespace=vm.namespace,
                name=dv_name,
            )
        )
        if not pvc_list:
            raise ResourceNotFoundError(
                f"PVC {dv_name} does not exist in namespace {namespace.name}"
            )
        pvc = pvc_list[0]
        pv = list(
            cluster_resource(PersistentVolume).get(
                dyn_client=admin_client,
                name=pvc.instance.spec.volumeName,
            )
        )[0]
        check_disk_count_in_vm(vm=vm)
        with ResourceEditor(
            patches={
                hostpath_provisioner_scope_module: HPP_NODE_PLACEMENT_DICT[
                    "node_selector"
                ]
            }
        ):
            # Wait for 1 hpp pod to be running, and for others to be deleted
            wait_for_desired_hpp_pods_running(
                hpp_daemonset=hpp_daemonset_scope_session, number_of_pods=1
            )
            vm.delete(wait=True)
        pvc.wait_deleted()
        pv.wait_deleted()
    # Wait for hpp pods to be restored
    wait_for_desired_hpp_pods_running(
        hpp_daemonset=hpp_daemonset_scope_session, number_of_pods=len(schedulable_nodes)
    )
