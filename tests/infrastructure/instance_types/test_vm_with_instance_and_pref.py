import pytest
from ocp_resources.controller_revision import ControllerRevision
from ocp_utilities.infra import cluster_resource

from utilities.constants import Images
from utilities.virt import VirtualMachineForTests, running_vm


pytestmark = [pytest.mark.post_upgrade, pytest.mark.sno]


@pytest.fixture(scope="class")
def rhel_vm_with_instance_type_and_preference(
    namespace, admin_client, instance_type_for_test_scope_class, vm_preference_for_test
):
    with instance_type_for_test_scope_class as vm_instance_type, vm_preference_for_test as vm_preference:
        with cluster_resource(VirtualMachineForTests)(
            client=admin_client,
            name="rhel-vm-with-instance-type",
            namespace=namespace.name,
            image=Images.Rhel.RHEL9_REGISTRY_GUEST_IMG,
            vm_instance_type=vm_instance_type,
            vm_preference=vm_preference,
        ) as vm:
            yield vm


@pytest.fixture()
def rhel_vm_spec(rhel_vm_with_instance_type_and_preference):
    return rhel_vm_with_instance_type_and_preference.instance.spec


@pytest.fixture()
def instance_controller_revision(
    rhel_vm_with_instance_type_and_preference, rhel_vm_spec
):
    return cluster_resource(ControllerRevision)(
        name=rhel_vm_spec.instancetype.revisionName,
        namespace=rhel_vm_with_instance_type_and_preference.namespace,
    )


@pytest.fixture()
def pref_controller_revision(rhel_vm_with_instance_type_and_preference, rhel_vm_spec):
    return cluster_resource(ControllerRevision)(
        name=rhel_vm_spec.preference.revisionName,
        namespace=rhel_vm_with_instance_type_and_preference.namespace,
    )


@pytest.mark.parametrize(
    "common_instance_type_param_dict, common_vm_preference_param_dict",
    [
        pytest.param(
            {
                "name": "basic",
                "cpu_cores": 1,
                "memory_requests": "1.5Gi",
            },
            {
                "name": "basic-vm-preference",
            },
        ),
    ],
    indirect=True,
)
class TestVmWithInstanceTypeAndPref:
    @pytest.mark.dependency(name="start_vm_with_instance_type_and_preference")
    @pytest.mark.polarion("CNV-9087")
    def test_start_vm_with_instance_type_and_preference(
        self, rhel_vm_with_instance_type_and_preference
    ):
        running_vm(vm=rhel_vm_with_instance_type_and_preference)

    @pytest.mark.dependency(depends=["start_vm_with_instance_type_and_preference"])
    @pytest.mark.polarion("CNV-9545")
    def test_instance_pref_controller_revision(
        self,
        rhel_vm_with_instance_type_and_preference,
        instance_controller_revision,
        pref_controller_revision,
    ):
        vm_name = rhel_vm_with_instance_type_and_preference.name
        assert (
            instance_controller_revision.exists
        ), "instance type controller revision was not created"
        assert (
            pref_controller_revision.exists
        ), "preference controller revision was not created"
        assert (
            instance_controller_revision.instance["metadata"]["ownerReferences"][0][
                "name"
            ]
            == vm_name
        )
        assert (
            pref_controller_revision.instance["metadata"]["ownerReferences"][0]["name"]
            == vm_name
        )

    # TODO add test to validate vmi data and controller revision edit once all bugs are fixed.
