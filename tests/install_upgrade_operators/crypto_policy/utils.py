import logging
from contextlib import contextmanager

import deepdiff
from benedict import benedict
from ocp_resources.cluster_operator import ClusterOperator
from ocp_resources.hyperconverged import HyperConverged
from ocp_resources.resource import Resource, ResourceEditor
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from ocp_utilities.infra import cluster_resource
from packaging.version import Version

from tests.install_upgrade_operators.constants import KEY_PATH_SEPARATOR
from tests.install_upgrade_operators.crypto_policy.constants import (
    CRYPTO_POLICY_EXPECTED_DICT,
    KEY_NAME_STR,
    MANAGED_CRS_LIST,
    MIN_TLS_VERSIONS,
    RESOURCE_NAME_STR,
    RESOURCE_NAMESPACE_STR,
    TLS_INTERMEDIATE_CIPHERS_IANA_OPENSSL_SYNTAX,
)
from utilities.constants import (
    CLUSTER,
    DEFAULT_RESOURCE_CONDITIONS,
    TIMEOUT_2MIN,
    TIMEOUT_15MIN,
    TLS_SECURITY_PROFILE,
)
from utilities.hco import ResourceEditorValidateHCOReconcile, wait_for_hco_conditions
from utilities.infra import ExecCommandOnPod
from utilities.ssp import verify_ssp_pod_is_running


LOGGER = logging.getLogger(__name__)


def get_resource_crypto_policy(admin_client, resource, name, key_name, namespace=None):
    """
    This function is used to get crypto policy settings associated with a resource

    Args:
        admin_client (DynamicClient): OCP Client to use.
        resource (Resource): Resource kind
        name (str): name of a resource
        key_name (str): full key path with separator
        namespace (str, optional): namespace for the resource

    Returns:
        dict: crypto policy settings value associated with the resource
    """
    kwargs = {"client": admin_client, "name": name}
    if namespace:
        kwargs["namespace"] = namespace
    resource_obj = cluster_resource(resource)(**kwargs)
    return benedict(
        resource_obj.instance.to_dict()["spec"], keypath_separator=KEY_PATH_SEPARATOR
    ).get(key_name)


def get_resources_crypto_policy_dict(
    admin_client, resources_dict, resources=MANAGED_CRS_LIST
):
    """
    This function collects crypto policy corresponding to each resources in the list
    'resources'

    Args:
        admin_client (DynamiClient): OCP Client to use.
        resources_dict (dict): Dict containing resource name, key_name, namespace
        resources (list): List of resource objects whose TLS policies are required

    Returns:
        dict: crypto policy settings value for each resource in 'resources'
    """
    return {
        resource: get_resource_crypto_policy(
            admin_client=admin_client,
            resource=resource,
            namespace=resources_dict[resource].get(RESOURCE_NAMESPACE_STR),
            name=resources_dict[resource][RESOURCE_NAME_STR],
            key_name=resources_dict[resource][KEY_NAME_STR],
        )
        for resource in resources
    }


def wait_for_crypto_policy_update(
    admin_client, resource, resource_namespace, resource_name, key_name, expected_policy
):
    sampler = TimeoutSampler(
        wait_timeout=TIMEOUT_2MIN,
        sleep=2,
        func=get_resource_crypto_policy,
        admin_client=admin_client,
        resource=resource,
        namespace=resource_namespace,
        name=resource_name,
        key_name=key_name,
    )
    sample = None
    try:
        for sample in sampler:
            # TODO: remove log message once the test and feature deemed to be stable
            LOGGER.info(
                f"{resource_name} actual: {sample}, expected: {expected_policy}"
            )
            if sample and not deepdiff.DeepDiff(
                sample,
                expected_policy,
                ignore_type_in_groups=[(benedict, dict)],
            ):
                return
    except TimeoutExpiredError:
        error_message = (
            f"For resource {resource} {resource_name}, expected policy {expected_policy},"
            f" did not match {sample} "
        )
        LOGGER.error(error_message)
        return error_message


def get_cluster_operator_status_conditions(admin_client, operator_conditions=None):
    operator_conditions = operator_conditions or DEFAULT_RESOURCE_CONDITIONS
    cluster_operator_status = {}
    for cluster_operator in list(
        cluster_resource(ClusterOperator).get(dyn_client=admin_client)
    ):
        operator_name = cluster_operator.name
        cluster_operator_status[operator_name] = {}
        for condition in cluster_operator.instance.get("status", {}).get(
            "conditions", []
        ):
            if condition["type"] in operator_conditions:
                if (
                    operator_name == "console"
                    and condition["type"] == Resource.Condition.DEGRADED
                    and condition["status"]
                    and "ConsoleNotificationSyncDegraded" in condition["message"]
                ):
                    cluster_operator_status[operator_name][
                        condition["type"]
                    ] = Resource.Condition.Status.FALSE
                else:
                    cluster_operator_status[operator_name][
                        condition["type"]
                    ] = condition["status"]

    return cluster_operator_status


def get_failed_cluster_operator(admin_client):
    cluster_operators_status_conditions = get_cluster_operator_status_conditions(
        admin_client=admin_client
    )
    failed_operators = {}
    for cluster_operator in cluster_operators_status_conditions:
        if sorted(
            cluster_operators_status_conditions[cluster_operator].items()
        ) != sorted(DEFAULT_RESOURCE_CONDITIONS.items()):
            LOGGER.info(
                f"{cluster_operator} current status condition: {cluster_operators_status_conditions[cluster_operator]}"
            )
            failed_operators[cluster_operator] = cluster_operators_status_conditions[
                cluster_operator
            ]
    return failed_operators


def wait_for_cluster_operator_stabilize(admin_client):
    sampler = TimeoutSampler(
        wait_timeout=TIMEOUT_15MIN,
        sleep=10,
        func=get_failed_cluster_operator,
        admin_client=admin_client,
    )
    consecutive_check = 0
    sample = None
    try:
        for sample in sampler:
            if not sample:
                LOGGER.info(f"Found stable cluster operator: {consecutive_check} time.")
                consecutive_check += 1
            else:
                LOGGER.info(
                    f"Following cluster operators are not yet stable: {sample}."
                )
                consecutive_check = 0
            if consecutive_check == 3:
                return

    except TimeoutExpiredError:
        LOGGER.error(f"Following cluster operators failed to stabilize: {sample}")
        if sample:
            raise


def assert_crypto_policy_propagated_to_components(
    admin_client,
    crypto_policy,
    resources_dict,
    updated_resource_kind,
):
    """
    This function is used to assert whether the updated crypto policy settings
    propagated to all CNV components - CDI, KubeVirt, CNAO & SSP

    Args:
        admin_client (DynamicClient): OCP Client to use.
        crypto_policy (str): Name of the policy ( "old" or "custom" )
        resources_dict (dict): values for resources(name,key_name,namespace_name)
                               in dict
        updated_resource_kind (str): Resource kind of the updated resource
            ( HyperConverged or APIServer )

    Raises:
        AssertionError: When TLS crypto policy of HCO managed CRs(KubeVirt, SSP, CNAO
        & CDI) doesn't match with the expected 'crypto_policy'
    """
    conflicting_resources = []
    for resource in MANAGED_CRS_LIST:
        expected_value = CRYPTO_POLICY_EXPECTED_DICT[crypto_policy][resource]
        error_message = wait_for_crypto_policy_update(
            admin_client=admin_client,
            resource=resource,
            resource_namespace=resources_dict[resource].get(RESOURCE_NAMESPACE_STR),
            resource_name=resources_dict[resource][RESOURCE_NAME_STR],
            key_name=resources_dict[resource][KEY_NAME_STR],
            expected_policy=expected_value,
        )
        if error_message:
            conflicting_resources.append(resource.kind)
    assert not conflicting_resources, (
        f"After updating the resource {updated_resource_kind} with {crypto_policy}, "
        f"following CRs are found inconsistent: {','.join(conflicting_resources)}"
    )


def assert_no_crypto_policy_in_hco(
    admin_client, crypto_policy, hco_namespace, hco_name
):
    hco_crypto_policy = get_resource_crypto_policy(
        admin_client=admin_client,
        resource=HyperConverged,
        name=hco_name,
        namespace=hco_namespace,
        key_name=TLS_SECURITY_PROFILE,
    )
    assert not hco_crypto_policy, (
        f"On updating APIServer {CLUSTER} with {crypto_policy}, HCO crypto policy "
        f"was set up to {hco_crypto_policy}:"
    )


def compose_openssl_command(service_spec, version, cipher="", extra_arguments=""):
    return (
        f"openssl s_client -connect {service_spec.clusterIP}:{service_spec.ports[0].port} "
        f"-tls{version.replace('.', '_')} {cipher} -brief <<< 'Q' 2>&1 {extra_arguments}"
    )


def assert_tls_version_connection(utility_pods, node, services, minimal_version):
    failed_service = {}
    for service in services:
        service_instance = service.instance
        service_name = service_instance.metadata.name
        LOGGER.info(f"Checking service: {service_name}")
        for version in set(MIN_TLS_VERSIONS.values()):
            cmd = compose_openssl_command(
                service_spec=service_instance.spec,
                version=version,
                extra_arguments="| grep 'Protocol version:'",
            )
            out = ExecCommandOnPod(utility_pods=utility_pods, node=node).exec(
                command=cmd, ignore_rc=True
            )
            # All TLS versions below the `minimal` configured version should be blocked
            if Version(version) < Version(minimal_version) and version in out:
                failed_service[service_name] = (
                    f"TLS v{version} should be blocked. "
                    f"Expected minimal v{minimal_version}"
                )

            # All versions equal or greater to `minimal` configured should be accepted (present in output)
            if Version(version) >= Version(minimal_version) and version not in out:
                failed_service[service_name] = (
                    f"Can't connect with TLS v{version}. "
                    f"Expected minimal v{minimal_version}"
                )

    assert not failed_service, f"Some services connections failed:\n {failed_service}"


def assert_tls_ciphers_blocked(
    utility_pods, node, services, tls_version, allowed_ciphers
):
    failed_service = {}
    for service in services:
        service_name = service.instance.metadata.name
        service_spec = service.instance.spec
        LOGGER.info(f"Checking service: {service_name}")
        for cipher_openssl in TLS_INTERMEDIATE_CIPHERS_IANA_OPENSSL_SYNTAX.values():
            # check only non-allowed ciphers, because not all explicitly set ciphers may be accepted by cluster itself
            if cipher_openssl not in allowed_ciphers:
                cmd = compose_openssl_command(
                    service_spec=service_spec,
                    version=tls_version,
                    cipher=f"-cipher {cipher_openssl}",
                    extra_arguments="| grep 'Ciphersuite:'",
                )
                out = ExecCommandOnPod(utility_pods=utility_pods, node=node).exec(
                    command=cmd, ignore_rc=True
                )
                if cipher_openssl in out:
                    failed_service[service_name] = (
                        f"Cipher {cipher_openssl} should be blocked. "
                        f"Allowed ciphers: {allowed_ciphers}"
                    )

    assert not failed_service, f"Some services connections failed:\n {failed_service}"


@contextmanager
def set_hco_crypto_policy(hco_resource, tls_spec):
    with ResourceEditorValidateHCOReconcile(
        patches={hco_resource: {"spec": {TLS_SECURITY_PROFILE: tls_spec}}},
        wait_for_reconcile_post_update=True,
        list_resource_reconcile=MANAGED_CRS_LIST,
    ):
        yield


@contextmanager
def update_apiserver_crypto_policy(
    admin_client,
    hco_namespace,
    apiserver,
    tls_spec,
):
    with ResourceEditor(
        patches={apiserver: {"spec": {TLS_SECURITY_PROFILE: tls_spec}}},
    ):
        verify_ssp_pod_is_running(dyn_client=admin_client, hco_namespace=hco_namespace)
        yield
    wait_for_cluster_operator_stabilize(admin_client=admin_client)
    verify_ssp_pod_is_running(dyn_client=admin_client, hco_namespace=hco_namespace)
    wait_for_hco_conditions(
        admin_client=admin_client,
        hco_namespace=hco_namespace,
        list_dependent_crs_to_check=MANAGED_CRS_LIST,
    )
