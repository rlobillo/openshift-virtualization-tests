"""
CDI Import
"""

import logging

import pytest

from tests.storage.constants import HPP_STORAGE_CLASSES
from utilities.constants import LINUX_BRIDGE
from utilities.network import network_device, network_nad


LOGGER = logging.getLogger(__name__)
BRIDGE_NAME = "br1-dv"


@pytest.fixture()
def skip_non_shared_storage(storage_class_matrix__function__):
    if [*storage_class_matrix__function__][0] in HPP_STORAGE_CLASSES:
        pytest.skip("Skipping when storage is non-shared")


@pytest.fixture()
def bridge_on_node():
    with network_device(
        interface_type=LINUX_BRIDGE,
        nncp_name=BRIDGE_NAME,
        interface_name=BRIDGE_NAME,
    ) as br:
        yield br


@pytest.fixture()
def linux_nad(namespace, bridge_on_node):
    with network_nad(
        namespace=namespace,
        nad_type=LINUX_BRIDGE,
        nad_name=f"{BRIDGE_NAME}-nad",
        interface_name=bridge_on_node.bridge_name,
    ) as nad:
        yield nad
