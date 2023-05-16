import base64
import logging
import os
import shlex

import pytest
from ocp_resources.configmap import ConfigMap
from ocp_resources.resource import ResourceEditor
from ocp_resources.secret import Secret
from ocp_resources.template import Template
from ocp_resources.utils import TimeoutSampler
from ocp_utilities.infra import cluster_resource
from ocp_utilities.utils import run_ssh_commands
from pytest_testconfig import py_config

from tests.compute.utils import get_windows_timezone
from tests.os_params import WINDOWS_2019, WINDOWS_2019_OS, WINDOWS_2019_TEMPLATE_LABELS
from utilities.constants import TCP_TIMEOUT_30SEC, TIMEOUT_5MIN
from utilities.virt import (
    VirtualMachineForTestsFromTemplate,
    migrate_vm_and_verify,
    running_vm,
)


LOGGER = logging.getLogger(__name__)


ANSWER_FILE_NAME = "autounattend.xml"
NEW_HOSTNAME = "Solaire-PC"
NEW_ADMIN_USERNAME = "Solaire"
NEW_ADMIN_PASSWORD = "Praisethesun123"
NEW_TIMEZONE = "AUS Eastern Standard Time"


def __get_sysprep_missing_autounattend_condition(vm):
    expected_error = f"Sysprep drive should contain {ANSWER_FILE_NAME}"
    return [
        condition
        for condition in vm.vmi.instance.status.conditions
        if expected_error in condition.get("message", "")
    ]


def verify_changes_from_autounattend(vm, timezone, hostname):
    # timezone
    LOGGER.info(f"Verifying timezone change from answer file in vm {vm.name}")
    actual_timezone = (
        get_windows_timezone(ssh_exec=vm.ssh_exec, get_standard_name=True)
        .split(":")[1]
        .strip()
    )
    assert (
        actual_timezone == timezone
    ), f"Incorrect timezone, expected {timezone}, found {actual_timezone}"

    # hostname
    LOGGER.info(f"Verifying hostname change from answer file in vm {vm.name}")
    actual_hostname = run_ssh_commands(
        host=vm.ssh_exec, commands=["hostname"], tcp_timeout=TCP_TIMEOUT_30SEC
    )[0].strip()
    assert (
        actual_hostname == hostname
    ), f"Incorrect hostname, expected {hostname}, found {actual_hostname}"


def verify_failed_boot_without_autounattend(vm):
    """A VM with a sysprep resource attached should not be able to start
    without a file present in that resource named autounattend.xml (case-insensitive).
    This function assumes this is the case and attempts to start the VM, then
    verifies that the expected error condition appears."""

    LOGGER.info(f"Starting VM {vm.name} without {ANSWER_FILE_NAME}")
    vm.start(wait=False)
    LOGGER.info("Waiting for error condition to appear")
    for sample in TimeoutSampler(
        wait_timeout=TIMEOUT_5MIN,
        sleep=1,
        func=__get_sysprep_missing_autounattend_condition,
        vm=vm,
    ):
        if sample:
            return True


def generate_sysprep_data(xml_string, resource_kind):
    if resource_kind == "ConfigMap":
        data_string = xml_string
    elif resource_kind == "Secret":
        data_string = base64.b64encode(s=bytes(xml_string, "ascii")).decode("ascii")

    return {"Autounattend.xml": data_string, "Unattend.xml": data_string}


@pytest.fixture(scope="class")
def sysprep_xml_string():
    xml_file_path = f"{os.path.dirname(os.path.realpath(__file__))}/sysprep_xml_files/unattend_{WINDOWS_2019_OS}.xml"

    with open(xml_file_path) as xml_file:
        return xml_file.read()


@pytest.fixture(scope="class")
def sysprep_resource(
    sysprep_source_matrix__class__, unprivileged_client, namespace, sysprep_xml_string
):
    LOGGER.info(f"Creating sysprep {sysprep_source_matrix__class__} resource")
    if sysprep_source_matrix__class__ == "ConfigMap":
        with cluster_resource(ConfigMap)(
            client=unprivileged_client,
            name="sysprep-config",
            namespace=namespace.name,
            data=generate_sysprep_data(
                xml_string=sysprep_xml_string, resource_kind="ConfigMap"
            ),
        ) as sysprep:
            yield sysprep
    elif sysprep_source_matrix__class__ == "Secret":
        with cluster_resource(Secret)(
            client=unprivileged_client,
            name="sysprep-secret",
            namespace=namespace.name,
            data_dict=generate_sysprep_data(
                xml_string=sysprep_xml_string, resource_kind="Secret"
            ),
        ) as sysprep:
            yield sysprep


@pytest.fixture(scope="class")
def sysprep_vm(
    sysprep_source_matrix__class__,
    golden_image_data_source_scope_class,
    unprivileged_client,
    namespace,
):
    with VirtualMachineForTestsFromTemplate(
        name=f"sysprep-{sysprep_source_matrix__class__.lower()}-vm",
        namespace=namespace.name,
        client=unprivileged_client,
        data_source=golden_image_data_source_scope_class,
        labels=Template.generate_template_labels(**WINDOWS_2019_TEMPLATE_LABELS),
    ) as vm:
        running_vm(vm=vm)
        yield vm


@pytest.fixture(scope="class")
def sealed_vm(sysprep_vm):
    """Runs the sysprep tool on sysprep_vm, preparing it to do an OS refresh using
    the provided answer file on next boot"""

    LOGGER.info(f"Sealing VM {sysprep_vm.name}")
    run_ssh_commands(
        host=sysprep_vm.ssh_exec,
        commands=shlex.split(
            "%WINDIR%\\system32\\sysprep\\sysprep.exe /generalize /quit /oobe /mode:vm",
            posix=False,
        ),
        tcp_timeout=TCP_TIMEOUT_30SEC,
    )


@pytest.fixture(scope="class")
def attached_sysprep_volume_to_vm(sysprep_resource, sysprep_vm):
    LOGGER.info(
        f"Attaching sysprep volume {sysprep_resource.name} to vm {sysprep_vm.name}"
    )

    disks = sysprep_vm.instance.spec.template.spec.domain.devices.disks
    disks.append({"name": "sysprep", "cdrom": {"bus": "sata"}})

    sysprep_resource_kind = (
        "configMap" if sysprep_resource.kind == "ConfigMap" else "secret"
    )

    volumes = sysprep_vm.instance.spec.template.spec.volumes
    volumes.append(
        {
            "name": "sysprep",
            "sysprep": {sysprep_resource_kind: {"name": sysprep_resource.name}},
        }
    )

    with ResourceEditor(
        patches={
            sysprep_vm: {
                "spec": {
                    "template": {
                        "spec": {
                            "domain": {
                                "devices": {"disks": disks},
                            },
                            "volumes": volumes,
                        },
                    }
                }
            }
        },
    ) as edits:

        sysprep_vm.username = NEW_ADMIN_USERNAME
        sysprep_vm.password = NEW_ADMIN_PASSWORD

        sysprep_vm.stop(wait=True)
        running_vm(vm=sysprep_vm)

        yield edits


@pytest.fixture()
def migrated_sysprep_vm(sysprep_vm):
    migrate_vm_and_verify(vm=sysprep_vm, check_ssh_connectivity=True)


@pytest.fixture()
def shutdown_and_removed_autounattend_from_sysprep_resource(
    sysprep_vm, sysprep_resource
):
    """Shuts down sysprep_vm and renames both answerfiles in the sysprep volume
    to prepare for a negative test case where a VM attached to a sysprep volume
    missing these files will fail to boot"""

    LOGGER.info(f"Removing {ANSWER_FILE_NAME} from sysprep volume")
    sysprep_vm.stop(wait=True)

    answer_file_str = sysprep_resource.instance.data["Autounattend.xml"]
    bad_data = {"aun.xml": answer_file_str, "un.xml": answer_file_str}

    edits = ResourceEditor(patches={sysprep_resource: {"data": None}})
    edits.update(backup_resources=True)

    ResourceEditor(patches={sysprep_resource: {"data": bad_data}}).update()

    yield

    LOGGER.info(f"Returning {ANSWER_FILE_NAME} to sysprep volume")
    sysprep_vm.stop(wait=True)
    edits.restore()
    running_vm(vm=sysprep_vm)


@pytest.fixture()
def detached_sysprep_resource_and_restarted_vm(
    sysprep_vm, attached_sysprep_volume_to_vm
):
    LOGGER.info(f"Detaching sysprep volume from vm {sysprep_vm.name}")
    sysprep_vm.stop(wait=True)
    attached_sysprep_volume_to_vm.restore()
    running_vm(vm=sysprep_vm)

    yield

    LOGGER.info(f"Re-attaching sysprep volume to vm {sysprep_vm.name}")
    sysprep_vm.stop(wait=True)
    attached_sysprep_volume_to_vm.update(backup_resources=True)
    running_vm(vm=sysprep_vm)


@pytest.mark.parametrize(
    "golden_image_data_volume_scope_class",
    [
        {
            "dv_name": WINDOWS_2019_OS,
            "image": WINDOWS_2019["image_path"],
            "dv_size": WINDOWS_2019["dv_size"],
            "storage_class": py_config["default_storage_class"],
        },
    ],
    indirect=True,
)
@pytest.mark.usefixtures("sysprep_vm", "sealed_vm", "attached_sysprep_volume_to_vm")
class TestSysprep:
    @pytest.mark.polarion("CNV-6760")
    def test_admin_user_locale_computer_name_after_boot(self, sysprep_vm):
        verify_changes_from_autounattend(
            vm=sysprep_vm, timezone=NEW_TIMEZONE, hostname=NEW_HOSTNAME
        )

    @pytest.mark.polarion("CNV-6761")
    def test_migrate_vm_with_sysprep_cm(self, sysprep_vm, migrated_sysprep_vm):
        verify_changes_from_autounattend(
            vm=sysprep_vm, timezone=NEW_TIMEZONE, hostname=NEW_HOSTNAME
        )

    @pytest.mark.polarion("CNV-6762")
    def test_remove_sysprep_volume_and_check_data_persistence(
        self, sysprep_vm, detached_sysprep_resource_and_restarted_vm
    ):
        verify_changes_from_autounattend(
            vm=sysprep_vm, timezone=NEW_TIMEZONE, hostname=NEW_HOSTNAME
        )

    @pytest.mark.polarion("CNV-6763")
    def test_remove_autounattend_and_boot(
        self, sysprep_vm, shutdown_and_removed_autounattend_from_sysprep_resource
    ):
        assert verify_failed_boot_without_autounattend(
            vm=sysprep_vm
        ), f"Error condition for missing {ANSWER_FILE_NAME} not met when attempting to start VM {sysprep_vm.name}"
