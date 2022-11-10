"""
Test network specific configurations when exposing a VM via a service.
"""

import pytest
from ocp_resources.service import Service

from utilities.constants import SSH_PORT_22
from utilities.infra import (
    MissingResourceException,
    cluster_resource,
    run_virtctl_command,
)
from utilities.network import compose_cloud_init_data_dict
from utilities.virt import VirtualMachineForTests, fedora_vm_body, running_vm


SINGLE_STACK_SERVICE_IP_FAMILY = "IPv4"

SERVICE_IP_FAMILY_POLICY_SINGLE_STACK = "SingleStack"
SERVICE_IP_FAMILY_POLICY_PREFER_DUAL_STACK = "PreferDualStack"
SERVICE_IP_FAMILY_POLICY_REQUIRE_DUAL_STACK = "RequireDualStack"


def basic_expose_command(vm, svc_name):
    return [
        "expose",
        "vm",
        vm,
        "--port=27017",
        f"--target-port={SSH_PORT_22}",
        "--type=NodePort",
        f"--name={svc_name}",
    ]


def find_svc(dyn_client, name, namespace):
    for svc in Service.get(
        dyn_client=dyn_client,
        name=name,
        namespace=namespace,
    ):
        return svc

    raise MissingResourceException(f"Service {name}.")


def assert_svc_ip_params(
    svc,
    expected_num_families_in_service,
    expected_ip_family_policy,
):
    assert (
        len(svc.instance.spec.ipFamilies) == expected_num_families_in_service
        and svc.instance.spec.ipFamilyPolicy == expected_ip_family_policy
    ), f"{expected_ip_family_policy} service wrongly created."


@pytest.fixture(scope="module")
def running_vm_for_exposure(
    worker_node1,
    namespace,
    unprivileged_client,
    dual_stack_network_data,
):
    vm_name = "exposed-vm"
    cloud_init_data = compose_cloud_init_data_dict(
        ipv6_network_data=dual_stack_network_data
    )

    with cluster_resource(VirtualMachineForTests)(
        namespace=namespace.name,
        name=vm_name,
        body=fedora_vm_body(name=vm_name),
        node_selector=worker_node1.hostname,
        cloud_init_data=cloud_init_data,
        client=unprivileged_client,
    ) as vm:
        running_vm(vm=vm, check_ssh_connectivity=False)
        yield vm


@pytest.fixture()
def single_stack_service(running_vm_for_exposure):
    running_vm_for_exposure.custom_service_enable(
        service_name="single-stack-svc",
        port=SSH_PORT_22,
        ip_families=[SINGLE_STACK_SERVICE_IP_FAMILY],
    )


@pytest.fixture()
def default_ip_family_policy_service(running_vm_for_exposure):
    running_vm_for_exposure.custom_service_enable(
        service_name="default-ip-family-policy-svc",
        port=SSH_PORT_22,
    )


@pytest.fixture()
def virtctl_expose_service(
    request,
    admin_client,
    running_vm_for_exposure,
    dual_stack_cluster,
):
    ip_family_policy = request.param
    if (
        ip_family_policy == SERVICE_IP_FAMILY_POLICY_REQUIRE_DUAL_STACK
        and not dual_stack_cluster
    ):
        pytest.skip(
            f"{SERVICE_IP_FAMILY_POLICY_REQUIRE_DUAL_STACK} service cannot be created in a non-dual-stack cluster."
        )

    svc_name = f"ssh-{ip_family_policy.lower()}-svc"
    expose_command = basic_expose_command(
        vm=running_vm_for_exposure.name, svc_name=svc_name
    )
    expose_command += [f"--ip-family-policy={ip_family_policy}"]
    res, output, err = run_virtctl_command(
        command=expose_command, namespace=running_vm_for_exposure.namespace
    )
    assert (
        res
    ), f"virtctl {expose_command} failed with error: {err}\n\tmessage: {output}"

    svc = find_svc(
        dyn_client=admin_client,
        name=svc_name,
        namespace=running_vm_for_exposure.namespace,
    )
    yield svc

    # Teardown
    svc.clean_up()


@pytest.fixture()
def expected_num_families_in_service(request, dual_stack_cluster):
    ip_family_policy = request.param
    if ip_family_policy != SERVICE_IP_FAMILY_POLICY_SINGLE_STACK and dual_stack_cluster:
        return 2
    return 1


class TestServiceConfigurationViaManifest:
    @pytest.mark.polarion("CNV-5789")
    def test_service_with_configured_ip_families(
        self,
        running_vm_for_exposure,
        single_stack_service,
    ):
        assert (
            len(running_vm_for_exposure.custom_service.instance.spec.ipFamilies) == 1
            and running_vm_for_exposure.custom_service.instance.spec.ipFamilies[0]
            == SINGLE_STACK_SERVICE_IP_FAMILY
        ), "Wrong ipFamilies set in service"

    @pytest.mark.polarion("CNV-5831")
    def test_service_with_default_ip_family_policy(
        self,
        running_vm_for_exposure,
        default_ip_family_policy_service,
    ):
        assert (
            running_vm_for_exposure.custom_service.instance.spec.ipFamilyPolicy
            == SERVICE_IP_FAMILY_POLICY_SINGLE_STACK
        ), "Service created with wrong default ipfamilyPolicy."


class TestServiceConfigurationViaVirtctl:
    @pytest.mark.parametrize(
        "virtctl_expose_service, expected_num_families_in_service, ip_family_policy",
        [
            pytest.param(
                SERVICE_IP_FAMILY_POLICY_SINGLE_STACK,
                SERVICE_IP_FAMILY_POLICY_SINGLE_STACK,
                SERVICE_IP_FAMILY_POLICY_SINGLE_STACK,
                marks=(pytest.mark.polarion("CNV-6454")),
            ),
            pytest.param(
                SERVICE_IP_FAMILY_POLICY_PREFER_DUAL_STACK,
                SERVICE_IP_FAMILY_POLICY_PREFER_DUAL_STACK,
                SERVICE_IP_FAMILY_POLICY_PREFER_DUAL_STACK,
                marks=(pytest.mark.polarion("CNV-6481")),
            ),
            pytest.param(
                SERVICE_IP_FAMILY_POLICY_REQUIRE_DUAL_STACK,
                SERVICE_IP_FAMILY_POLICY_REQUIRE_DUAL_STACK,
                SERVICE_IP_FAMILY_POLICY_REQUIRE_DUAL_STACK,
                marks=(pytest.mark.polarion("CNV-6482")),
            ),
        ],
        indirect=["virtctl_expose_service", "expected_num_families_in_service"],
    )
    def test_vitrctl_expose_services(
        self,
        expected_num_families_in_service,
        running_vm_for_exposure,
        virtctl_expose_service,
        dual_stack_cluster,
        ip_family_policy,
    ):
        assert_svc_ip_params(
            svc=virtctl_expose_service,
            expected_num_families_in_service=expected_num_families_in_service,
            expected_ip_family_policy=ip_family_policy,
        )
