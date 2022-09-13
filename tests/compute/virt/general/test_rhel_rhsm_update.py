# -*- coding: utf-8 -*-

"""
RHSM account was created using http://account-manager-stage.app.eng.rdu2.redhat.com/#create
Username: cnv-qe-auto-stage, password:
Account subscriptions: qum5net
ESA0001 - Red Hat Enterprise Linux, Premium
RH00076 - Red Hat Enterprise Linux High Touch Beta
"""

import logging
import shlex

import pytest
from ocp_utilities.utils import run_ssh_commands
from pytest_testconfig import config as py_config

from tests.compute.utils import (
    generate_attached_rhsm_secret_dict,
    generate_rhsm_cloud_init_data,
    register_vm_to_rhsm,
)
from tests.os_params import RHEL_LATEST, RHEL_LATEST_LABELS, RHEL_LATEST_OS
from utilities.virt import vm_instance_from_template


LOGGER = logging.getLogger(__name__)


@pytest.fixture()
def rhsm_cloud_init_data():
    return generate_rhsm_cloud_init_data()


@pytest.fixture()
def rhsm_vm(
    request,
    unprivileged_client,
    namespace,
    golden_image_data_source_scope_function,
    rhsm_cloud_init_data,
):
    with vm_instance_from_template(
        request=request,
        unprivileged_client=unprivileged_client,
        namespace=namespace,
        data_source=golden_image_data_source_scope_function,
        cloud_init_data=rhsm_cloud_init_data,
    ) as rhsm_vm:
        yield rhsm_vm


@pytest.fixture()
def registered_rhsm(rhsm_vm):
    return register_vm_to_rhsm(vm=rhsm_vm)


@pytest.mark.parametrize(
    "golden_image_data_volume_scope_function, rhsm_vm",
    [
        pytest.param(
            {
                "dv_name": RHEL_LATEST_OS,
                "image": RHEL_LATEST["image_path"],
                "storage_class": py_config["default_storage_class"],
                "dv_size": RHEL_LATEST["dv_size"],
            },
            {
                "vm_name": "rhel-rhsm-vm",
                "template_labels": RHEL_LATEST_LABELS,
                "attached_secret": generate_attached_rhsm_secret_dict(),
            },
            marks=pytest.mark.polarion("CNV-4006"),
        ),
    ],
    indirect=True,
)
def test_rhel_yum_update(
    skip_upstream,
    unprivileged_client,
    namespace,
    rhsm_created_secret,
    golden_image_data_volume_scope_function,
    rhsm_vm,
    registered_rhsm,
):
    run_ssh_commands(
        host=rhsm_vm.ssh_exec,
        commands=shlex.split("sudo yum update -y curl"),
    )
