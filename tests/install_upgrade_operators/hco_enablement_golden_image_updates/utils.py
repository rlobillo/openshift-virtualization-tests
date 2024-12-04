import logging
import re

from ocp_resources.cdi import CDI
from ocp_resources.data_import_cron import DataImportCron
from ocp_resources.data_source import DataSource
from ocp_resources.ssp import SSP
from openshift.dynamic.exceptions import ResourceNotFoundError

from utilities.constants import SSP_CR_COMMON_TEMPLATES_LIST_KEY_NAME
from utilities.hco import ResourceEditorValidateHCOReconcile, wait_for_hco_conditions
from utilities.ssp import wait_for_ssp_conditions


HCO_CR_DATA_IMPORT_SCHEDULE_KEY = "dataImportSchedule"
RE_NAMED_GROUP_MINUTES = "minutes"
RE_NAMED_GROUP_HOURS = "hours"
DATA_IMPORT_SCHEDULE_RANDOM_MINUTES_REGEX = (
    rf"(?P<{RE_NAMED_GROUP_MINUTES}>\d+)\s+"
    rf"(?P<{RE_NAMED_GROUP_HOURS}>\d+)\/12\s+\*\s+\*\s+\*\s*$"
)
COMMON_TEMPLATE = "commonTemplate"
DATASOURCE_NAME = "custom-datasource"

DATA_IMPORT_CRON_ENABLE = (
    f"metadata->annotations->{DataImportCron.ApiGroup.DATA_IMPORT_CRON_TEMPLATE_KUBEVIRT_IO}/"
    "enable"
)
CUSTOM_CRON_TEMPLATE = {
    "metadata": {
        "annotations": {
            "cdi.kubevirt.io/storage.bind.immediate.requested": "false",
        },
        "name": "custom-test-cron",
    },
    "spec": {
        "garbageCollect": "Outdated",
        "managedDataSource": DATASOURCE_NAME,
        "schedule": "* * * * *",
        "template": {
            "metadata": {},
            "spec": {
                "source": {
                    "registry": {
                        "imageStream": "custom-test-guest",
                        "pullMethod": "node",
                    },
                },
                "storage": {
                    "resources": {
                        "requests": {
                            "storage": "7Gi",
                        }
                    }
                },
            },
        },
    },
}
LOGGER = logging.getLogger(__name__)


def get_random_minutes_hours_fields_from_data_import_schedule(target_string):
    """
    Gets the minutes field from the dataImportSchedule field in HCO CR

    Args:
        target_string (str): dataImportSchedule string (crontab format)

    Raises:
        AssertionError: raised if the regex pattern did not find a match
    """
    re_result = re.match(DATA_IMPORT_SCHEDULE_RANDOM_MINUTES_REGEX, target_string)
    assert re_result, (
        "No regex match against the string: "
        f"regex={DATA_IMPORT_SCHEDULE_RANDOM_MINUTES_REGEX} target_value={target_string}"
    )
    return re_result.group(RE_NAMED_GROUP_MINUTES), re_result.group(
        RE_NAMED_GROUP_HOURS
    )


def get_modifed_common_template_names(hyperconverged):
    return [
        template["metadata"]["name"]
        for template in get_templates_by_type_from_hco_status(
            hco_status_templates=hyperconverged.instance.to_dict()["status"][
                SSP_CR_COMMON_TEMPLATES_LIST_KEY_NAME
            ],
        )
        if template["status"].get("modified")
    ]


def get_templates_by_type_from_hco_status(
    hco_status_templates, template_type=COMMON_TEMPLATE
):
    return [
        template
        for template in hco_status_templates
        if (template_type == COMMON_TEMPLATE and template["status"].get(template_type))
        or (
            template_type == "customTemplate"
            and not template["status"].get(COMMON_TEMPLATE)
        )
    ]


def wait_for_auto_boot_config_stabilization(admin_client, hco_namespace):
    wait_for_ssp_conditions(admin_client=admin_client, hco_namespace=hco_namespace)
    wait_for_hco_conditions(admin_client=admin_client, hco_namespace=hco_namespace)


def get_data_import_cron_by_name(namespace, cron_name):
    data_import_cron = DataImportCron(name=cron_name, namespace=namespace)
    if data_import_cron.exists:
        return data_import_cron
    raise ResourceNotFoundError(
        f"DataImportCron: {data_import_cron} not found in namespace: {namespace}"
    )


def get_template_dict_by_name(template_name, templates):
    for template in templates:
        if template["metadata"]["name"] == template_name:
            return template


def update_custom_template(
    admin_client,
    hco_namespace,
    hyperconverged_spec,
    custom_template,
    golden_images_namespace,
):
    with ResourceEditorValidateHCOReconcile(
        patches={
            hyperconverged_spec: {
                "spec": {SSP_CR_COMMON_TEMPLATES_LIST_KEY_NAME: [custom_template]}
            }
        },
        list_resource_reconcile=[SSP, CDI],
        wait_for_reconcile_post_update=True,
    ):
        wait_for_auto_boot_config_stabilization(
            admin_client=admin_client, hco_namespace=hco_namespace
        )
        yield
    # delete the datasource associated with custom template that was created earlier, as it won't be cleaned up
    # otherwise
    DataSource(
        client=admin_client,
        name=DATASOURCE_NAME,
        namespace=golden_images_namespace.name,
    ).clean_up()
