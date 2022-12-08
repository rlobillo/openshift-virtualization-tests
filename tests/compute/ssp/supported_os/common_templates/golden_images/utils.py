import logging

from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler

from utilities.constants import TIMEOUT_2MIN


LOGGER = logging.getLogger(__name__)


def assert_missing_golden_image_pvc(vm, pvc_name):
    def _verify_missing_pvc_in_vm_conditions(_conditions, _expected_message):
        if _conditions:
            return any(
                [_expected_message in condition["message"] for condition in _conditions]
            )

    expected_message = "VMI does not exist"

    try:
        # Verify VM error on missing source PVC
        for sample in TimeoutSampler(
            wait_timeout=TIMEOUT_2MIN,
            sleep=5,
            func=_verify_missing_pvc_in_vm_conditions,
            _conditions=vm.instance.status.conditions,
            _expected_message=expected_message,
        ):
            if sample:
                break
    except TimeoutExpiredError:
        LOGGER.error(
            f"VM {vm.name} condition message does not contain '{expected_message}', "
            f"conditions: {vm.instance.status.conditions}"
        )
        raise
