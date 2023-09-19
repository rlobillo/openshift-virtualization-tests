import pytest
from kubernetes.dynamic.exceptions import ResourceNotFoundError
from ocp_resources.network import Network

from utilities.constants import CLUSTER


@pytest.fixture(scope="session")
def network_overhead(ovn_kubernetes_cluster):
    # The cluster network overlay overhead that should be subtracted from the cluster MTU, based on
    # https://docs.openshift.com/container-platform/4.12/networking/changing-cluster-network-mtu.html#mtu-value-selection_changing-cluster-network-mtu
    return 100 if ovn_kubernetes_cluster else 50


@pytest.fixture(scope="session")
def cluster_network_mtu():
    network_resource = Network(name=CLUSTER)
    if not network_resource.exists:
        raise ResourceNotFoundError(f"{CLUSTER} Network resource not found.")
    return network_resource.instance.status.clusterNetworkMTU


@pytest.fixture(scope="session")
def cluster_hardware_mtu(network_overhead, cluster_network_mtu):
    # cluster_network_mtu contains the pod network MTU. We should add to it the network overlay to get the hardware MTU.
    return cluster_network_mtu + network_overhead
