import pytest

from tests.chaos.constants import CHAOS_LABEL
from utilities.infra import label_nodes


@pytest.fixture()
def vm_node_with_chaos_label(vm_with_nginx_service):
    yield from label_nodes(nodes=[vm_with_nginx_service.vmi.node], labels=CHAOS_LABEL)
