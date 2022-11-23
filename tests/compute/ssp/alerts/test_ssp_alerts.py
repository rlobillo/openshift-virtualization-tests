import pytest
from ocp_resources.deployment import Deployment
from ocp_resources.prometheus_rule import PrometheusRule
from ocp_resources.template import Template
from ocp_resources.utils import TimeoutSampler
from openshift.dynamic.exceptions import UnprocessibleEntityError

from tests.compute.utils import verify_no_listed_alerts_on_cluster
from tests.os_params import FEDORA_LATEST_LABELS
from utilities.constants import SSP_OPERATOR, TIMEOUT_3MIN, VIRT_TEMPLATE_VALIDATOR
from utilities.hco import ResourceEditorValidateHCOReconcile
from utilities.infra import get_pod_by_name_prefix
from utilities.ssp import wait_for_ssp_conditions
from utilities.virt import VirtualMachineForTestsFromTemplate


SSP_DOWN = "SSPDown"
SSP_TEMPLATE_VALIDATOR_DOWN = "SSPTemplateValidatorDown"
SSP_COMMON_TEMPLATES_MODIFICATION_REVERTED = "SSPCommonTemplatesModificationReverted"
SSP_HIGH_RATE_REJECTED_VMS = "SSPHighRateRejectedVms"
SSP_FAILING_TO_RECONCILE = "SSPFailingToReconcile"

SSP_ALERTS_LIST = [
    SSP_DOWN,
    SSP_TEMPLATE_VALIDATOR_DOWN,
    SSP_FAILING_TO_RECONCILE,
]


def verify_ssp_pod_is_running(dyn_client, hco_namespace):
    pod = get_pod_by_name_prefix(
        dyn_client=dyn_client,
        pod_prefix=SSP_OPERATOR,
        namespace=hco_namespace.name,
    )
    pod.wait_for_status(status=pod.Status.RUNNING)


def alert_not_firing_sampler(prometheus, alert):
    """
    This function gives some time for alerts to remove Firing state
    """
    sampler = TimeoutSampler(
        wait_timeout=TIMEOUT_3MIN,
        sleep=1,
        func=prometheus.get_alert,
        alert=alert,
    )
    for sample in sampler:
        if not sample or sample[0]["metric"]["alertstate"] != "firing":
            return


@pytest.fixture()
def paused_ssp_operator(admin_client, hco_namespace, ssp_resource_scope_function):
    """
    Pause ssp-operator to avoid from reconciling any related objects
    """
    with ResourceEditorValidateHCOReconcile(
        patches={
            ssp_resource_scope_function: {
                "metadata": {"annotations": {"kubevirt.io/operator.paused": "true"}}
            }
        }
    ):
        yield
    wait_for_ssp_conditions(admin_client=admin_client, hco_namespace=hco_namespace)


@pytest.fixture()
def template_validator_finalizer(hco_namespace):
    deployment = Deployment(name=VIRT_TEMPLATE_VALIDATOR, namespace=hco_namespace.name)
    with ResourceEditorValidateHCOReconcile(
        patches={
            deployment: {
                "metadata": {"finalizers": ["ssp.kubernetes.io/temporary-finalizer"]}
            }
        }
    ):
        yield


@pytest.fixture()
def deleted_ssp_operator_pod(admin_client, hco_namespace):
    get_pod_by_name_prefix(
        dyn_client=admin_client,
        pod_prefix=SSP_OPERATOR,
        namespace=hco_namespace.name,
    ).delete(wait=True)
    yield
    verify_ssp_pod_is_running(dyn_client=admin_client, hco_namespace=hco_namespace)


@pytest.fixture()
def template_modified(admin_client, base_templates):
    with ResourceEditorValidateHCOReconcile(
        patches={
            base_templates[0]: {
                "metadata": {"annotations": {"description": "New Description"}}
            }
        }
    ):
        yield


@pytest.fixture()
def prometheus_k8s_rules_cnv(hco_namespace):
    return PrometheusRule(name="prometheus-k8s-rules-cnv", namespace=hco_namespace.name)


@pytest.fixture()
def prometheus_existing_records(prometheus_k8s_rules_cnv):
    return prometheus_k8s_rules_cnv.instance.to_dict()["spec"]["groups"][0]["rules"]


@pytest.fixture()
def modified_metrics_timer(
    request, prometheus_k8s_rules_cnv, prometheus_existing_records
):
    """This fixture sets the timer to 5 min

    Some of metrics have 1hr timer so running tests too often may result in tests failing
    """
    rule_record = request.param
    assert [
        rule
        for rule in prometheus_existing_records
        if rule.get("record") == rule_record
    ], f"The record rule {rule_record} was not found in a Prometheus"

    for rule in prometheus_existing_records:
        if rule.get("record") == rule_record:
            rule.update({"expr": rule["expr"].replace("[1h]", "[5m]")})

    with ResourceEditorValidateHCOReconcile(
        patches={
            prometheus_k8s_rules_cnv: {
                "spec": {
                    "groups": [
                        {"name": "cnv.rules", "rules": prometheus_existing_records}
                    ]
                }
            }
        }
    ):
        yield


@pytest.fixture()
def high_rate_rejected_vms_metric(prometheus_existing_records):
    for rule in prometheus_existing_records:
        if rule.get("alert") == SSP_HIGH_RATE_REJECTED_VMS:
            return int(rule["expr"][-1])


@pytest.fixture()
def created_multiple_failed_vms_from_template(
    unprivileged_client,
    namespace,
    high_rate_rejected_vms_metric,
):
    """
    This fixture is trying to create wrong VMs from a template multiple times for getting alert triggered
    """
    for _ in range(high_rate_rejected_vms_metric + 1):
        with pytest.raises(UnprocessibleEntityError):
            with VirtualMachineForTestsFromTemplate(
                name="non-creatable-vm",
                namespace=namespace.name,
                client=unprivileged_client,
                labels=Template.generate_template_labels(**FEDORA_LATEST_LABELS),
                diskless_vm=True,
                memory_requests="10Mi",
            ) as vm:
                return vm


class TestSSPAlerts:
    @pytest.mark.polarion("CNV-7612")
    def test_no_ssp_alerts_on_healthy_cluster(
        self,
        prometheus,
    ):
        verify_no_listed_alerts_on_cluster(
            prometheus=prometheus, alerts_list=SSP_ALERTS_LIST
        )

    @pytest.mark.parametrize(
        "modified_metrics_timer, alert",
        [
            pytest.param(
                "kubevirt_ssp_common_templates_restored_total",
                SSP_COMMON_TEMPLATES_MODIFICATION_REVERTED,
                marks=pytest.mark.polarion("CNV-8097"),
            ),
            pytest.param(
                "kubevirt_ssp_rejected_vms_total",
                SSP_HIGH_RATE_REJECTED_VMS,
                marks=pytest.mark.polarion("CNV-8098"),
            ),
        ],
        indirect=["modified_metrics_timer"],
    )
    def test_no_additional_ssp_alerts_on_healthy_cluster(
        self,
        prometheus,
        paused_ssp_operator,
        modified_metrics_timer,
        alert,
    ):
        alert_not_firing_sampler(prometheus=prometheus, alert=alert)

    @pytest.mark.order(after="test_no_ssp_alerts_on_healthy_cluster")
    @pytest.mark.parametrize(
        "scaled_deployment, alert_not_firing",
        [
            pytest.param(
                {"deployment_name": VIRT_TEMPLATE_VALIDATOR, "replicas": 0},
                SSP_TEMPLATE_VALIDATOR_DOWN,
                marks=pytest.mark.polarion("CNV-7615"),
            ),
            pytest.param(
                {"deployment_name": SSP_OPERATOR, "replicas": 0},
                SSP_DOWN,
                marks=pytest.mark.polarion("CNV-7614"),
            ),
        ],
        indirect=True,
    )
    def test_alert_ssp_pods_down(
        self,
        prometheus,
        alert_not_firing,
        paused_ssp_operator,
        scaled_deployment,
    ):
        prometheus.alert_sampler(alert=alert_not_firing)

    @pytest.mark.order(after="test_no_ssp_alerts_on_healthy_cluster")
    @pytest.mark.parametrize(
        "alert_not_firing",
        [
            pytest.param(
                SSP_FAILING_TO_RECONCILE,
                marks=pytest.mark.polarion("CNV-7711"),
            ),
        ],
        indirect=True,
    )
    def test_alert_ssp_failing_to_reconcile(
        self,
        prometheus,
        alert_not_firing,
        paused_ssp_operator,
        template_validator_finalizer,
        deleted_ssp_operator_pod,
    ):
        prometheus.alert_sampler(alert=alert_not_firing)

    @pytest.mark.order(after="test_no_additional_ssp_alerts_on_healthy_cluster")
    @pytest.mark.parametrize(
        "alert_not_firing",
        [
            pytest.param(
                SSP_COMMON_TEMPLATES_MODIFICATION_REVERTED,
                marks=pytest.mark.polarion("CNV-7616"),
            ),
        ],
        indirect=True,
    )
    def test_alert_template_modification_reverted(
        self,
        prometheus,
        alert_not_firing,
        template_modified,
    ):
        prometheus.alert_sampler(alert=alert_not_firing)

    @pytest.mark.order(after="test_no_additional_ssp_alerts_on_healthy_cluster")
    @pytest.mark.parametrize(
        "alert_not_firing",
        [
            pytest.param(
                SSP_HIGH_RATE_REJECTED_VMS,
                marks=pytest.mark.polarion("CNV-7707"),
            ),
        ],
        indirect=True,
    )
    def test_alert_high_rate_rejected_vms(
        self,
        prometheus,
        alert_not_firing,
        created_multiple_failed_vms_from_template,
    ):
        prometheus.alert_sampler(alert=alert_not_firing)
