import logging

from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from ocp_resources.virtual_machine_instance import VirtualMachineInstance

from utilities.constants import TIMEOUT_5MIN, TIMEOUT_5SEC
from utilities.virt import taint_node_no_schedule


LOGGER = logging.getLogger(__name__)


def verify_vmi_was_migrated(initial_node, vm):
    try:
        for sample in TimeoutSampler(
            wait_timeout=TIMEOUT_5MIN,
            sleep=TIMEOUT_5SEC,
            func=lambda: vm.vmi.node.name != initial_node.name
            and vm.vmi.status == VirtualMachineInstance.Status.RUNNING,
        ):
            if sample:
                LOGGER.info(
                    f"The VM was created on {initial_node.name}, "
                    f"and has successfully been migrated to {vm.vmi.node.name}"
                )
                return True
    except TimeoutExpiredError:
        LOGGER.error(
            f"The VMI on {initial_node.name} has not been migrated to a different node."
        )
        raise


def taint_node_for_migration(initial_node):
    with taint_node_no_schedule(node=initial_node):
        yield initial_node
