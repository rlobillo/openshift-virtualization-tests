import logging

from ocp_resources.utils import TimeoutSampler
from openshift.dynamic.exceptions import NotFoundError

from utilities.constants import TIMEOUT_2MIN
from utilities.infra import get_pod_by_name_prefix


LOGGER = logging.getLogger(__name__)


def wait_for_kubemacpool_pods_error_state(dyn_client, hco_namespace):
    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_2MIN,
        sleep=1,
        func=get_pod_by_name_prefix,
        dyn_client=dyn_client,
        pod_prefix="kubemacpool",
        namespace=hco_namespace.name,
        get_all=True,
    )
    for sample in samples:
        try:
            if any([pod.status == pod.Status.PENDING for pod in sample]):
                return

        except NotFoundError:
            LOGGER.error("Pods not Found")
