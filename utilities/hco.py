import json
import logging

from ocp_resources.cdi import CDI
from ocp_resources.hyperconverged import HyperConverged
from ocp_resources.kubevirt import KubeVirt
from ocp_resources.namespace import Namespace
from ocp_resources.network_addons_config import NetworkAddonsConfig
from ocp_resources.resource import Resource, ResourceEditor
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from openshift.dynamic.exceptions import ResourceNotFoundError
from pytest_testconfig import py_config

import utilities.infra
from utilities.constants import (
    DEFAULT_HCO_CONDITIONS,
    ENABLE_COMMON_BOOT_IMAGE_IMPORT_FEATURE_GATE,
    EXPECTED_STATUS_CONDITIONS,
    HCO_SUBSCRIPTION,
    IMAGE_CRON_STR,
    TIMEOUT_2MIN,
    TIMEOUT_4MIN,
    TIMEOUT_10MIN,
    TIMEOUT_30MIN,
    StorageClassNames,
)
from utilities.ssp import (
    verify_ssp_pod_is_running,
    wait_for_at_least_one_auto_update_data_import_cron,
    wait_for_deleted_data_import_crons,
    wait_for_ssp_conditions,
)


LOGGER = logging.getLogger(__name__)

DEFAULT_HCO_PROGRESSING_CONDITIONS = {
    Resource.Condition.PROGRESSING: Resource.Condition.Status.TRUE,
}
HCO_JSONPATCH_ANNOTATION_COMPONENT_DICT = {
    "kubevirt": {
        "api_group_prefix": "kubevirt",
        "config": "configuration/",
    },
    "cdi": {
        "api_group_prefix": "containerizeddataimporter",
        "config": "config/",
    },
    "cnao": {
        "api_group_prefix": "networkaddonsconfigs",
    },
}


class ResourceEditorValidateHCOReconcile(ResourceEditor):
    def __init__(
        self,
        hco_namespace="openshift-cnv",
        consecutive_checks_count=3,
        list_resource_reconcile=None,
        wait_for_reconcile_post_update=False,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.admin_client = utilities.infra.get_admin_client()
        self.hco_namespace = Namespace(client=self.admin_client, name=hco_namespace)
        self.wait_for_reconcile_post_update = wait_for_reconcile_post_update
        self._consecutive_checks_count = consecutive_checks_count
        self.list_resource_reconcile = list_resource_reconcile or []
        # TODO: Remove this variable when https://issues.redhat.com/browse/CNV-23504 is fixed
        self.hco_crypto_policy_update = utilities.infra.is_jira_open(
            jira_id="CNV-23504"
        )

    def update(self, backup_resources=False):
        super().update(backup_resources=backup_resources)
        if self.wait_for_reconcile_post_update:
            # TODO: Remove this check when https://issues.redhat.com/browse/CNV-23504 is fixed
            if self.hco_crypto_policy_update:
                verify_ssp_pod_is_running(
                    dyn_client=self.admin_client,
                    hco_namespace=self.hco_namespace,
                )
            wait_for_hco_conditions(
                admin_client=self.admin_client,
                hco_namespace=self.hco_namespace,
                consecutive_checks_count=self._consecutive_checks_count,
                list_dependent_crs_to_check=self.list_resource_reconcile,
            )

    def restore(self):
        super().restore()
        # TODO: Remove this check when https://issues.redhat.com/browse/CNV-23504 is fixed
        if self.hco_crypto_policy_update:
            verify_ssp_pod_is_running(
                dyn_client=self.admin_client,
                hco_namespace=self.hco_namespace,
            )
        wait_for_hco_conditions(
            admin_client=self.admin_client,
            hco_namespace=self.hco_namespace,
            consecutive_checks_count=self._consecutive_checks_count,
            list_dependent_crs_to_check=self.list_resource_reconcile,
        )


def wait_for_hco_conditions(
    admin_client,
    hco_namespace,
    expected_conditions=None,
    wait_timeout=TIMEOUT_10MIN,
    sleep=5,
    consecutive_checks_count=3,
    condition_key1="type",
    condition_key2="status",
    list_dependent_crs_to_check=None,
):
    """
    Checking HCO conditions.

    If list_dependent_crs_to_check information is passed, we would wait for them to
    stabilize first, before checking hco.status.conditions. Please note, EXPECTED_STATUS_CONDITIONS defines what all
    CRs can be checked currently. Any new CRs and associated default conditions need to be added in
    EXPECTED_STATUS_CONDITIONS in order for option list_dependent_crs_to_check to work as expected.
    """
    if list_dependent_crs_to_check:
        LOGGER.info(
            f"Waiting for {len(list_dependent_crs_to_check)} CRs managed by HCO to reconcile: "
        )
        for resource in list_dependent_crs_to_check:
            utilities.infra.wait_for_consistent_resource_conditions(
                dynamic_client=admin_client,
                namespace=getattr(resource, "namespace", None),
                resource_kind=resource,
                expected_conditions=EXPECTED_STATUS_CONDITIONS[resource],
                consecutive_checks_count=consecutive_checks_count,
            )
    utilities.infra.wait_for_consistent_resource_conditions(
        dynamic_client=admin_client,
        namespace=hco_namespace.name,
        expected_conditions=expected_conditions or DEFAULT_HCO_CONDITIONS,
        resource_kind=HyperConverged,
        condition_key1=condition_key1,
        condition_key2=condition_key2,
        total_timeout=wait_timeout,
        polling_interval=sleep,
        consecutive_checks_count=consecutive_checks_count,
    )


def wait_for_ds(ds):
    LOGGER.info(f"Waiting for daemonset {ds.name} to be up to date.")
    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_4MIN,
        sleep=5,
        func=lambda: ds.instance.to_dict(),
    )
    try:
        for sample in samples:
            status = sample.get("status")
            metadata = sample.get("metadata")
            if metadata.get("generation") == status.get("observedGeneration") and (
                status.get("desiredNumberScheduled")
                == status.get("currentNumberScheduled")
                == status.get("updatedNumberScheduled")
            ):
                break
    except TimeoutExpiredError:
        LOGGER.error(f"Timeout waiting for daemonset {ds.name} to be up to date.")
        raise


def wait_for_dp(dp):
    LOGGER.info(f"Waiting for deployment {dp.name} to be up to date.")
    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_4MIN,
        sleep=5,
        func=lambda: dp.instance.to_dict(),
    )
    try:
        for sample in samples:
            status = sample.get("status")
            metadata = sample.get("metadata")
            if metadata.get("generation") == status.get(
                "observedGeneration"
            ) and status.get("replicas") == status.get("updatedReplicas"):
                break
    except TimeoutExpiredError:
        LOGGER.error(f"Timeout waiting for deployment {dp.name} to be up to date.")
        raise


def apply_np_changes(
    admin_client, hco, hco_namespace, infra_placement=None, workloads_placement=None
):
    current_infra = hco.instance.to_dict()["spec"].get("infra")
    current_workloads = hco.instance.to_dict()["spec"].get("workloads")
    target_infra = infra_placement if infra_placement is not None else current_infra
    target_workloads = (
        workloads_placement if workloads_placement is not None else current_workloads
    )
    if target_workloads != current_workloads or target_infra != current_infra:
        patch = {
            "spec": {
                "infra": target_infra or None,
                "workloads": target_workloads or None,
            }
        }
        LOGGER.info(f"Updating HCO with node placement. {patch}")
        editor = ResourceEditor(patches={hco: patch})
        editor.update(backup_resources=False)
        wait_for_hco_post_update_stable_state(
            admin_client=admin_client, hco_namespace=hco_namespace
        )
    else:
        LOGGER.info("No actual changes to node placement configuration, skipping")


def wait_for_hco_post_update_stable_state(admin_client, hco_namespace):
    """
    Waits for hco to reach stable state post hco update

    Args:
        admin_client (DynamicClient): Dynamic client object
        hco_namespace (Namespace): Namespace object
    """
    LOGGER.info(
        "Waiting for all HCO conditions to detect that it's back to a stable configuration."
    )
    wait_for_hco_conditions(
        admin_client=admin_client,
        hco_namespace=hco_namespace,
        consecutive_checks_count=6,
        list_dependent_crs_to_check=[CDI, NetworkAddonsConfig, KubeVirt],
    )
    # unfortunately at this time we are not really done:
    # HCO propagated the change to components operators that propagated it
    # to their operands (deployments and daemonsets)
    # so all the CNV operators reports progressing=False and even HCO reports progressing=False
    # but deployment and daemonsets controllers has still to kill and restart pods.
    # with the following lines we can wait for all the deployment and daemonsets in
    # openshift-cnv namespace to be back to uptodate status.
    # The main issue is that if we check it too fast, we can even check before
    # deployment and daemonsets controller report uptodate=false.
    # We have also to compare the observedGeneration with the generation number
    # to be sure that the relevant controller already updated the status
    for ds in utilities.infra.get_daemonsets(
        admin_client=admin_client, namespace=hco_namespace.name
    ):
        # We need to skip checking "hostpath-provisioner" daemonset, since it is not managed by HCO CR
        if not ds.name.startswith(StorageClassNames.HOSTPATH):
            wait_for_ds(ds=ds)
    for deployment in utilities.infra.get_deployments(
        admin_client=admin_client,
        namespace=hco_namespace.name,
    ):
        wait_for_dp(dp=deployment)
    utilities.infra.wait_for_pods_running(
        admin_client=admin_client,
        namespace=hco_namespace,
        number_of_consecutive_checks=3,
        filter_pods_by_name=IMAGE_CRON_STR,
    )


def add_labels_to_nodes(nodes, node_labels):
    """
    Adds given labels to a list of nodes

    Args:
        nodes (list): list of nodes
        node_labels (dict): dictionary of labels to be applied

    Returns:
        dictionary with information on labels applied for all the nodes and associated resource editors for the same

    """
    node_resources = {}
    for index, node in enumerate(nodes, start=1):
        labels = {key: f"{value}{index}" for key, value in node_labels.items()}
        node_resource = ResourceEditor(patches={node: {"metadata": {"labels": labels}}})
        node_resource.update(backup_resources=True)
        node_resources[node_resource] = {"node": node.name, "labels": labels}
    return node_resources


def get_hco_spec(admin_client, hco_namespace):
    return utilities.infra.get_hyperconverged_resource(
        client=admin_client, hco_ns_name=hco_namespace.name
    ).instance.to_dict()["spec"]


def get_installed_hco_csv(admin_client, hco_namespace):
    cnv_subscription = utilities.infra.get_subscription(
        admin_client=admin_client,
        namespace=hco_namespace.name,
        subscription_name=py_config["hco_subscription"] or HCO_SUBSCRIPTION,
    )
    return utilities.infra.get_csv_by_name(
        csv_name=cnv_subscription.instance.status.installedCSV,
        admin_client=admin_client,
        namespace=hco_namespace.name,
    )


def get_hco_version(client, hco_ns_name):
    """
    Get current hco version

    Args:
        client (DynamicClient): Dynamic client object
        hco_ns_name (str): hco namespace name

    Returns:
        str: hyperconverged operator version
    """
    return (
        utilities.infra.get_hyperconverged_resource(
            client=client, hco_ns_name=hco_ns_name
        )
        .instance.status.versions[0]
        .version
    )


def wait_for_hco_version(client, hco_ns_name, cnv_version):
    """
    Wait for hco version to get updated.

    Args:
        client (DynamicClient): Dynamic client object
        hco_ns_name (str): hco namespace name
        cnv_version (str): cnv version string that should match with current cnv version

    Returns:
        str: hco version string

    Raises:
        TimeoutExpiredError: if hco resource is not updated with expected version string
    """
    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_30MIN,
        sleep=5,
        func=get_hco_version,
        client=client,
        hco_ns_name=hco_ns_name,
    )
    sample = None
    try:
        for sample in samples:
            if sample and sample == cnv_version:
                LOGGER.info(f"HCO version updated to {cnv_version}")
                return sample
    except TimeoutExpiredError:
        LOGGER.error(
            f"Expected HCO version: {cnv_version}, actual hco version: {sample}"
        )
        raise


def disable_common_boot_image_import_feature_gate(
    admin_client,
    hco_resource,
    golden_images_namespace,
    golden_images_data_import_crons,
):
    if hco_resource.instance.spec.featureGates[
        ENABLE_COMMON_BOOT_IMAGE_IMPORT_FEATURE_GATE
    ]:
        update_common_boot_image_import_feature_gate(
            hco_resource=hco_resource,
            enable_feature_gate=False,
        )
        wait_for_deleted_data_import_crons(
            data_import_crons=golden_images_data_import_crons
        )
        yield
        # Always enable enableCommonBootImageImport feature gate after test execution
        enable_common_boot_image_import_feature_gate_wait_for_data_import_cron(
            hco_resource=hco_resource,
            admin_client=admin_client,
            namespace=golden_images_namespace,
        )
    else:
        yield


def enable_common_boot_image_import_feature_gate_wait_for_data_import_cron(
    hco_resource, admin_client, namespace
):
    hco_namespace = Namespace(name=hco_resource.namespace)
    update_common_boot_image_import_feature_gate(
        hco_resource=hco_resource,
        enable_feature_gate=True,
    )
    wait_for_at_least_one_auto_update_data_import_cron(
        admin_client=admin_client, namespace=namespace
    )
    wait_for_ssp_conditions(admin_client=admin_client, hco_namespace=hco_namespace)
    wait_for_hco_conditions(admin_client=admin_client, hco_namespace=hco_namespace)


def update_common_boot_image_import_feature_gate(hco_resource, enable_feature_gate):
    def _wait_for_feature_gate_update(_hco_resource, _enable_feature_gate):
        LOGGER.info(
            f"Wait for HCO {ENABLE_COMMON_BOOT_IMAGE_IMPORT_FEATURE_GATE} "
            f"feature gate to be set to {_enable_feature_gate}."
        )
        try:
            for sample in TimeoutSampler(
                wait_timeout=TIMEOUT_2MIN,
                sleep=5,
                func=lambda: _hco_resource.instance.spec.featureGates[
                    ENABLE_COMMON_BOOT_IMAGE_IMPORT_FEATURE_GATE
                ]
                == _enable_feature_gate,
            ):
                if sample:
                    return
        except TimeoutExpiredError:
            LOGGER.error(
                f"{ENABLE_COMMON_BOOT_IMAGE_IMPORT_FEATURE_GATE} was not updated to {_enable_feature_gate}"
            )
            raise

    editor = ResourceEditor(
        patches={
            hco_resource: {
                "spec": {
                    "featureGates": {
                        ENABLE_COMMON_BOOT_IMAGE_IMPORT_FEATURE_GATE: enable_feature_gate
                    }
                }
            }
        },
    )
    editor.update(backup_resources=True)
    _wait_for_feature_gate_update(
        _hco_resource=hco_resource, _enable_feature_gate=enable_feature_gate
    )


def get_hco_namespace(admin_client, namespace="openshift-cnv"):
    hco_ns = Namespace(client=admin_client, name=namespace)
    if hco_ns.exists:
        return hco_ns
    raise ResourceNotFoundError(f"Namespace: {namespace} not found.")


def hco_cr_jsonpatch_annotations_dict(component, path, value, op="add"):
    # https://github.com/kubevirt/hyperconverged-cluster-operator/blob/master/docs/cluster-configuration.md#jsonpatch-annotations
    component_dict = HCO_JSONPATCH_ANNOTATION_COMPONENT_DICT[component]
    return {
        "metadata": {
            "annotations": {
                f"{component_dict['api_group_prefix']}.{Resource.ApiGroup.KUBEVIRT_IO}/jsonpatch": json.dumps(
                    [
                        {
                            "op": op,
                            "path": f"/spec/{component_dict.get('config', '')}{path}",
                            "value": value,
                        }
                    ]
                )
            }
        }
    }
