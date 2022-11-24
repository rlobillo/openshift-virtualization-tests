import logging

from ocp_resources.utils import TimeoutSampler
from ocp_resources.virtual_machine_instance import VirtualMachineInstance

from utilities.constants import TIMEOUT_5MIN, TIMEOUT_5SEC


LOGGER = logging.getLogger(__name__)


def verify_vmi_migration(initial_node, vm):
    for sample in TimeoutSampler(
        wait_timeout=TIMEOUT_5MIN,
        sleep=TIMEOUT_5SEC,
        func=lambda: vm.vmi.node.name != initial_node.name
        and vm.vmi.status == VirtualMachineInstance.Status.RUNNING,
    ):
        if sample:
            LOGGER.info(
                f"The VM was created on {initial_node.name}, and has successfully been migrated to {vm.vmi.node.name}"
            )
            return True
