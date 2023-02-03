import pytest

from tests.chaos.migration.utils import taint_node_for_migration


@pytest.fixture()
def tainted_node_for_vm_chaos_rhel9_migration(chaos_vm_rhel9):
    yield from taint_node_for_migration(initial_node=chaos_vm_rhel9.vmi.node)


@pytest.fixture()
def tainted_node_for_vm_nginx_migration(vm_with_nginx_service):
    yield from taint_node_for_migration(initial_node=vm_with_nginx_service.vmi.node)


@pytest.fixture()
def tainted_node_for_vm_chaos_rhel9_with_dv_migration(chaos_vm_rhel9_with_dv_started):
    yield from taint_node_for_migration(
        initial_node=chaos_vm_rhel9_with_dv_started.vmi.node
    )
