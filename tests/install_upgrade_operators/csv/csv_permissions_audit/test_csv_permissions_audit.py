import logging

import pytest
import yaml
from dictdiffer import diff
from pytest_testconfig import config as py_config

from tests.install_upgrade_operators.csv.csv_permissions_audit.utils import (
    get_csv_permissions,
    get_global_permissions,
    get_yaml_file_path,
)


LOGGER = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def csv_permissions():
    return get_csv_permissions(namespace=py_config["hco_namespace"])


@pytest.fixture
def csv_permissions_from_yaml():
    with open(get_yaml_file_path(), "r") as fd:
        return yaml.safe_load(fd)


@pytest.mark.polarion("CNV-9547")
def test_compare_csv_permissions(csv_permissions_from_yaml, csv_permissions):
    _diff = list(diff(csv_permissions_from_yaml, csv_permissions))
    assert not (
        _diff
    ), f"Found unexpected differences in CNV CSV permissions compare to saved permissions in {get_yaml_file_path()}"


# FIXME: SSP: https://issues.redhat.com/browse/CNV-24031
# FIXME: Network: https://issues.redhat.com/browse/CNV-24032
@pytest.mark.polarion("CNV-9548")
def test_global_csv_permissions(csv_permissions):
    errors = {}
    for service_account_name, all_permissions in csv_permissions.items():
        permission = all_permissions.get("permission", [])
        cluster_permission = all_permissions.get("cluster_permission", [])
        for _permissions, dict_key in zip(
            [permission, cluster_permission], ["permission", "cluster_permission"]
        ):
            get_global_permissions(
                errors_dict=errors,
                permissions=_permissions,
                service_account_name=service_account_name,
                key_name=dict_key,
            )

    if errors:
        LOGGER.error(yaml.dump(errors))
        raise AssertionError("Found global permission for some serviceAccounts")
