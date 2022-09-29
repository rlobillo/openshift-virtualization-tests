import logging
import multiprocessing
import random

from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler

from utilities.constants import TIMEOUT_1MIN, TIMEOUT_5SEC
from utilities.infra import get_pod_by_name_prefix


LOGGER = logging.getLogger(__name__)


def create_pod_deleting_process(
    dyn_client,
    pod_prefix,
    namespace_name,
    ratio,
    interval=TIMEOUT_5SEC,
    max_duration=TIMEOUT_1MIN,
):
    """
    Creates a process that, when started,
    continuously deletes pods for a certain amount of time or until the process is stopped.

    Args:
        dyn_client (DynamicClient)
        pod_prefix (str): Pod name prefix used to find the pods to be deleted.
        namespace_name (str): Name of the namespace were the pods to be deleted live.
        ratio (float): Percentage of pods to be deleted (expressed as a fraction between 0 and 1).
        interval (int): Interval that determines how often the pods will be deleted.
        max_duration (int): Maximum time that the process will be running.

    Returns:
        multiprocessing.Process: Process that continuously deletes pods.

    Example:
        pod_deleting_process = create_pod_deleting_process(
            dyn_client=admin_client, pod_prefix="apiserver",
            namespace_name="openshift-apiserver", ratio=0.5, interval=5, max_duration=180
        )
        pod_deleting_process.start()
        ...
        pod_deleting_process.terminate()
    """

    def _choose_surviving_pods(dyn_client, pod_prefix, namespace_name, ratio):
        initial_pods = get_pod_by_name_prefix(
            dyn_client=dyn_client,
            pod_prefix=pod_prefix,
            namespace=namespace_name,
            get_all=True,
        )
        number_of_deleted_pods = round(number=ratio * len(initial_pods))
        LOGGER.info(
            f"Number of pods to delete: {number_of_deleted_pods} out of {len(initial_pods)}."
        )
        surviving_pods = [
            pod
            for pod in random.sample(
                population=initial_pods, k=len(initial_pods) - number_of_deleted_pods
            )
        ]
        LOGGER.info(f"Surviving pods: {[pod.name for pod in surviving_pods]}")

        return surviving_pods

    def _delete_pods(dyn_client, pod_prefix, namespace_name, surviving_pods):
        deleted_pods = get_pod_by_name_prefix(
            dyn_client=dyn_client,
            pod_prefix=pod_prefix,
            namespace=namespace_name,
            get_all=True,
        )
        for pod in deleted_pods:
            if pod.name not in [surviving_pod.name for surviving_pod in surviving_pods]:
                pod.delete()

    def _delete_pods_continuously(
        dyn_client, pod_prefix, namespace_name, ratio, interval, max_duration
    ):
        surviving_pods = _choose_surviving_pods(
            dyn_client=dyn_client,
            pod_prefix=pod_prefix,
            namespace_name=namespace_name,
            ratio=ratio,
        )

        try:
            for _ in TimeoutSampler(
                wait_timeout=max_duration,
                sleep=interval,
                func=_delete_pods,
                dyn_client=dyn_client,
                pod_prefix=pod_prefix,
                namespace_name=namespace_name,
                surviving_pods=surviving_pods,
            ):
                pass
        except TimeoutExpiredError:
            LOGGER.info("Pod deleting process finished.")

    return multiprocessing.Process(
        target=_delete_pods_continuously,
        args=(
            dyn_client,
            pod_prefix,
            namespace_name,
            ratio,
            interval,
            max_duration,
        ),
    )
