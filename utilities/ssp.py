import logging
import re

from ocp_resources.data_import_cron import DataImportCron
from ocp_resources.ssp import SSP
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from openshift.dynamic.exceptions import NotFoundError
from pytest_testconfig import config as py_config

import utilities.infra
import utilities.storage
from utilities.constants import (
    DEFAULT_RESOURCE_CONDITIONS,
    SSP_KUBEVIRT_HYPERCONVERGED,
    SSP_OPERATOR,
    TIMEOUT_2MIN,
    TIMEOUT_3MIN,
    TIMEOUT_6MIN,
    TIMEOUT_10SEC,
)


LOGGER = logging.getLogger(__name__)


def wait_for_deleted_data_import_crons(data_import_crons):
    def _get_existing_data_import_crons(
        _data_import_crons, _auto_boot_data_import_cron_prefixes
    ):
        return [
            data_import_cron.name
            for data_import_cron in _data_import_crons
            if data_import_cron.exists
            and re.sub(
                utilities.storage.DATA_IMPORT_CRON_SUFFIX, "", data_import_cron.name
            )
            in _auto_boot_data_import_cron_prefixes
        ]

    LOGGER.info("Wait for DataImportCrons deletion.")
    auto_boot_data_import_cron_prefixes = matrix_auto_boot_data_import_cron_prefixes()
    sample = None
    try:
        for sample in TimeoutSampler(
            wait_timeout=TIMEOUT_2MIN,
            sleep=5,
            func=_get_existing_data_import_crons,
            _data_import_crons=data_import_crons,
            _auto_boot_data_import_cron_prefixes=auto_boot_data_import_cron_prefixes,
        ):
            if not sample:
                return
    except TimeoutExpiredError:
        LOGGER.error(f"Some DataImportCrons are not deleted: {sample}")
        raise


def wait_for_at_least_one_auto_update_data_import_cron(admin_client, namespace):
    try:
        for sample in TimeoutSampler(
            wait_timeout=TIMEOUT_2MIN,
            sleep=5,
            func=get_data_import_crons,
            admin_client=admin_client,
            namespace=namespace,
        ):
            if sample:
                return
    except TimeoutExpiredError:
        LOGGER.error(f"No DataImportCrons found in {namespace.name}")
        raise


def matrix_auto_boot_data_import_cron_prefixes():
    data_import_cron_prefixes = []
    for data_source_matrix_entry in py_config["auto_update_data_source_matrix"]:
        data_source_name = [*data_source_matrix_entry][0]
        data_import_cron_prefixes.append(
            data_source_matrix_entry[data_source_name].get(
                "data_import_cron_prefix", data_source_name
            )
        )

    return data_import_cron_prefixes


def get_data_import_crons(admin_client, namespace):
    return list(DataImportCron.get(dyn_client=admin_client, namespace=namespace.name))


def get_ssp_resource(admin_client, namespace):
    try:
        for ssp in SSP.get(
            dyn_client=admin_client,
            name=SSP_KUBEVIRT_HYPERCONVERGED,
            namespace=namespace.name,
        ):
            return ssp
    except NotFoundError:
        LOGGER.error(
            f"SSP CR {SSP_KUBEVIRT_HYPERCONVERGED} was not found in namespace {namespace.name}"
        )
        raise


def wait_for_ssp_conditions(
    admin_client,
    hco_namespace,
    polling_interval=5,
    consecutive_checks_count=3,
    expected_conditions=None,
):
    utilities.infra.wait_for_consistent_resource_conditions(
        dynamic_client=admin_client,
        namespace=hco_namespace.name,
        expected_conditions=expected_conditions or DEFAULT_RESOURCE_CONDITIONS,
        resource_kind=SSP,
        condition_key1="type",
        condition_key2="status",
        total_timeout=TIMEOUT_3MIN,
        polling_interval=polling_interval,
        consecutive_checks_count=consecutive_checks_count,
    )


def is_ssp_pod_running(dyn_client, hco_namespace):
    pod = utilities.infra.get_pod_by_name_prefix(
        dyn_client=dyn_client,
        pod_prefix=SSP_OPERATOR,
        namespace=hco_namespace.name,
    )
    return (
        pod.instance.status.phase == pod.Status.RUNNING
        and pod.instance.status.containerStatuses[0]["ready"]
    )


def verify_ssp_pod_is_running(
    dyn_client,
    hco_namespace,
    wait_timeout=TIMEOUT_6MIN,
    sleep=TIMEOUT_10SEC,
    consecutive_checks_count=3,
):
    """
    Verifies that SSP pod is up and running

    This function polls for the status of SSP pod every 'sleep' seconds for
    the maximum time duration of 'wait_timeout', before it raises
    'TimeoutExpiredError'. Also this function makes sure that SSP pod
    is up and running for at least 'consecutive_checks_count'

    Args:
        dyn_client (DynamicClient): Dynamic client object
        hco_namespace (Namespace): Namespace object
        wait_timeout (int) : Maximum time to wait till SSP pod is up
        sleep (int): polling interval
        consecutive_checks_count (int): Minimum repetitive check iteration before
            assuring that SSP pod is up.

    Raises:
        'TimeoutExpiredError' when SSP pod is not up and running
         for the time duration of 'wait_timeout'
    """
    sampler = TimeoutSampler(
        wait_timeout=wait_timeout,
        sleep=sleep,
        func=is_ssp_pod_running,
        dyn_client=dyn_client,
        hco_namespace=hco_namespace,
    )
    sample = None
    checks_count = 0
    try:
        for sample in sampler:
            if sample:
                checks_count += 1
                if checks_count == consecutive_checks_count:
                    return
            else:
                checks_count = 0
    except TimeoutExpiredError:
        if sample:
            LOGGER.warning(
                f"SSP pod is up, but not for the last {consecutive_checks_count} "
                "consecutive checks"
            )
        else:
            LOGGER.error(f"SSP pod was not running for last {TIMEOUT_6MIN} seconds")
            raise
