# -*- coding: utf-8 -*-

import pytest
from ocp_resources.template import Template
from packaging import version

from tests.compute.ssp.supported_os.utils import get_linux_guest_agent_version
from tests.compute.utils import (
    start_and_fetch_processid_on_linux_vm,
    start_and_fetch_processid_on_windows_vm,
)
from utilities.infra import cluster_resource
from utilities.storage import create_or_update_data_source, data_volume
from utilities.virt import VirtualMachineForTestsFromTemplate


@pytest.fixture(scope="class")
def golden_image_data_volume_multi_rhel_os_multi_storage_scope_class(
    admin_client,
    golden_images_namespace,
    storage_class_matrix__class__,
    schedulable_nodes,
    rhel_os_matrix__class__,
):
    yield from data_volume(
        namespace=golden_images_namespace,
        storage_class_matrix=storage_class_matrix__class__,
        schedulable_nodes=schedulable_nodes,
        os_matrix=rhel_os_matrix__class__,
        check_dv_exists=True,
        admin_client=admin_client,
    )


@pytest.fixture(scope="class")
def golden_image_data_source_multi_rhel_os_multi_storage_scope_class(
    admin_client, golden_image_data_volume_multi_rhel_os_multi_storage_scope_class
):
    yield from create_or_update_data_source(
        admin_client=admin_client,
        dv=golden_image_data_volume_multi_rhel_os_multi_storage_scope_class,
    )


@pytest.fixture(scope="class")
def golden_image_data_volume_multi_windows_os_multi_storage_scope_class(
    admin_client,
    golden_images_namespace,
    storage_class_matrix__class__,
    schedulable_nodes,
    windows_os_matrix__class__,
):
    yield from data_volume(
        namespace=golden_images_namespace,
        storage_class_matrix=storage_class_matrix__class__,
        schedulable_nodes=schedulable_nodes,
        os_matrix=windows_os_matrix__class__,
        check_dv_exists=True,
        admin_client=admin_client,
    )


@pytest.fixture(scope="class")
def golden_image_data_source_multi_windows_os_multi_storage_scope_class(
    admin_client, golden_image_data_volume_multi_windows_os_multi_storage_scope_class
):
    yield from create_or_update_data_source(
        admin_client=admin_client,
        dv=golden_image_data_volume_multi_windows_os_multi_storage_scope_class,
    )


@pytest.fixture(scope="class")
def golden_image_data_volume_multi_fedora_os_multi_storage_scope_class(
    admin_client,
    golden_images_namespace,
    storage_class_matrix__class__,
    schedulable_nodes,
    fedora_os_matrix__class__,
):
    yield from data_volume(
        namespace=golden_images_namespace,
        storage_class_matrix=storage_class_matrix__class__,
        schedulable_nodes=schedulable_nodes,
        os_matrix=fedora_os_matrix__class__,
        check_dv_exists=True,
        admin_client=admin_client,
    )


@pytest.fixture(scope="class")
def golden_image_data_source_multi_fedora_os_multi_storage_scope_class(
    admin_client, golden_image_data_volume_multi_fedora_os_multi_storage_scope_class
):
    yield from create_or_update_data_source(
        admin_client=admin_client,
        dv=golden_image_data_volume_multi_fedora_os_multi_storage_scope_class,
    )


@pytest.fixture(scope="class")
def golden_image_data_volume_multi_centos_multi_storage_scope_class(
    admin_client,
    golden_images_namespace,
    storage_class_matrix__class__,
    schedulable_nodes,
    centos_os_matrix__class__,
):
    yield from data_volume(
        namespace=golden_images_namespace,
        storage_class_matrix=storage_class_matrix__class__,
        schedulable_nodes=schedulable_nodes,
        os_matrix=centos_os_matrix__class__,
        check_dv_exists=True,
        admin_client=admin_client,
    )


@pytest.fixture(scope="class")
def golden_image_data_source_multi_centos_multi_storage_scope_class(
    admin_client, golden_image_data_volume_multi_centos_multi_storage_scope_class
):
    yield from create_or_update_data_source(
        admin_client=admin_client,
        dv=golden_image_data_volume_multi_centos_multi_storage_scope_class,
    )


def vm_object_from_template(
    unprivileged_client,
    namespace,
    data_source_object,
    request=None,
    os_matrix=None,
):
    """Instantiate a VM object

    The call to this function is triggered by calling either
    golden_image_vm_object_from_template_multi_storage_scope_function or
    golden_image_vm_object_from_template_multi_storage_scope_class.
    """

    param_dict = request.param if request else {}
    rhel6 = False

    if os_matrix:
        os_matrix_key = [*os_matrix][0]
        vm_name = os_matrix_key
        labels = Template.generate_template_labels(
            **os_matrix[os_matrix_key]["template_labels"]
        )
        rhel6 = "rhel-6" in os_matrix_key
    else:
        vm_name = request.param["vm_name"].replace(".", "-").lower()
        labels = Template.generate_template_labels(**request.param["template_labels"])

    return cluster_resource(VirtualMachineForTestsFromTemplate)(
        name=vm_name,
        namespace=namespace.name,
        client=unprivileged_client,
        data_source=data_source_object,
        labels=labels,
        vm_dict=param_dict.get("vm_dict"),
        cpu_threads=param_dict.get("cpu_threads"),
        memory_requests=param_dict.get("memory_requests"),
        network_model=param_dict.get("network_model"),
        network_multiqueue=param_dict.get("network_multiqueue"),
        ssh=param_dict.get("ssh", True),
        systemctl_support=not rhel6,
        disable_sha2_algorithms=rhel6,
    )


@pytest.fixture()
def golden_image_vm_object_from_template_multi_storage_scope_function(
    request,
    unprivileged_client,
    namespace,
    golden_image_data_source_multi_storage_scope_function,
):
    return vm_object_from_template(
        request=request,
        unprivileged_client=unprivileged_client,
        namespace=namespace,
        data_source_object=golden_image_data_source_multi_storage_scope_function,
    )


@pytest.fixture()
def golden_image_vm_object_from_template_multi_storage_dv_scope_class_vm_scope_function(
    request,
    unprivileged_client,
    namespace,
    golden_image_data_source_multi_storage_scope_class,
):
    """VM is created with function scope whereas golden image DV is created with class scope. to be used when a number
    of tests (each creates its relevant VM) are gathered under a class and use the same golden image DV.
    """
    return vm_object_from_template(
        request=request,
        unprivileged_client=unprivileged_client,
        namespace=namespace,
        data_source_object=golden_image_data_source_multi_storage_scope_class,
    )


@pytest.fixture(scope="class")
def golden_image_vm_object_from_template_multi_storage_scope_class(
    request,
    unprivileged_client,
    namespace,
    golden_image_data_source_multi_storage_scope_class,
):
    return vm_object_from_template(
        request=request,
        unprivileged_client=unprivileged_client,
        namespace=namespace,
        data_source_object=golden_image_data_source_multi_storage_scope_class,
    )


@pytest.fixture(scope="class")
def golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class(
    unprivileged_client,
    namespace,
    rhel_os_matrix__class__,
    golden_image_data_source_multi_rhel_os_multi_storage_scope_class,
):
    return vm_object_from_template(
        unprivileged_client=unprivileged_client,
        namespace=namespace,
        os_matrix=rhel_os_matrix__class__,
        data_source_object=golden_image_data_source_multi_rhel_os_multi_storage_scope_class,
    )


@pytest.fixture(scope="class")
def golden_image_vm_object_from_template_multi_windows_os_multi_storage_scope_class(
    request,
    cluster_cpu_model_scope_class,
    unprivileged_client,
    namespace,
    windows_os_matrix__class__,
    golden_image_data_source_multi_windows_os_multi_storage_scope_class,
):
    return vm_object_from_template(
        request=request,
        unprivileged_client=unprivileged_client,
        namespace=namespace,
        os_matrix=windows_os_matrix__class__,
        data_source_object=golden_image_data_source_multi_windows_os_multi_storage_scope_class,
    )


@pytest.fixture(scope="class")
def golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class(
    request,
    cluster_cpu_model_scope_class,
    unprivileged_client,
    namespace,
    fedora_os_matrix__class__,
    golden_image_data_source_multi_fedora_os_multi_storage_scope_class,
):
    return vm_object_from_template(
        request=request,
        unprivileged_client=unprivileged_client,
        namespace=namespace,
        os_matrix=fedora_os_matrix__class__,
        data_source_object=golden_image_data_source_multi_fedora_os_multi_storage_scope_class,
    )


@pytest.fixture(scope="class")
def golden_image_vm_object_from_template_multi_centos_multi_storage_scope_class(
    cluster_cpu_model_scope_class,
    unprivileged_client,
    namespace,
    centos_os_matrix__class__,
    golden_image_data_source_multi_centos_multi_storage_scope_class,
):
    return vm_object_from_template(
        unprivileged_client=unprivileged_client,
        namespace=namespace,
        os_matrix=centos_os_matrix__class__,
        data_source_object=golden_image_data_source_multi_centos_multi_storage_scope_class,
    )


@pytest.fixture()
def skip_guest_agent_on_rhel6(rhel_os_matrix__class__):
    if "rhel-6" in [*rhel_os_matrix__class__][0]:
        pytest.skip("RHEL6 does not have guest agent")


@pytest.fixture()
def skip_if_os_version_below_rhel9(rhel_os_matrix__class__):
    if version.parse([*rhel_os_matrix__class__][0]) < version.parse("rhel-9"):
        pytest.skip("EFI is not enabled by default before RHEL9")


@pytest.fixture()
def skip_efi_if_win_ver_below_11_or_win_server(windows_os_matrix__class__):
    parsed_os_ver = version.parse(version=[*windows_os_matrix__class__][0])
    if parsed_os_ver < version.parse("11"):
        pytest.skip("EFI is enabled by default only on Windows 11 and above")
    if parsed_os_ver > version.parse("2000"):
        pytest.skip("EFI is not enabled by default on Windows servers")


@pytest.fixture()
def skip_win_11_on_fips_enabled_cluster(
    fips_enabled_cluster, windows_os_matrix__class__
):
    if fips_enabled_cluster and "win-11" in [*windows_os_matrix__class__][0]:
        pytest.skip("Skip Win-11 test on FIPS enabled cluster (BZ 2089301)")


@pytest.fixture()
def skip_guest_agent_on_win12(windows_os_matrix__class__):
    if "win-2012" in [*windows_os_matrix__class__][0]:
        pytest.skip("win-2012 doesn't support powershell commands")


def skip_on_guest_agent_version(vm, ga_version):
    qemu_guest_agent_version = get_linux_guest_agent_version(ssh_exec=vm.ssh_exec)
    if version.parse(qemu_guest_agent_version.split()[0]) < version.parse(ga_version):
        pytest.skip("Skipping on guest agent version {qemu_guest_agent_version}")


@pytest.fixture()
def skip_guest_agent_on_rhel(
    golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
):
    skip_on_guest_agent_version(
        vm=golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
        ga_version="4.2.0",
    )


@pytest.fixture()
def skip_guest_agent_on_centos(
    golden_image_vm_object_from_template_multi_centos_multi_storage_scope_class,
):
    skip_on_guest_agent_version(
        vm=golden_image_vm_object_from_template_multi_centos_multi_storage_scope_class,
        ga_version="4.2.0",
    )


@pytest.fixture(scope="class")
def powershell_process_in_windows_os(
    golden_image_vm_object_from_template_multi_windows_os_multi_storage_scope_class,
):
    return start_and_fetch_processid_on_windows_vm(
        vm=golden_image_vm_object_from_template_multi_windows_os_multi_storage_scope_class,
        process_name="powershell.exe",
    )


@pytest.fixture(scope="class")
def ping_process_in_fedora_os(
    golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
):
    process_name = "ping"
    return start_and_fetch_processid_on_linux_vm(
        vm=golden_image_vm_object_from_template_multi_fedora_os_multi_storage_scope_class,
        process_name=process_name,
        args="localhost",
    )


@pytest.fixture(scope="class")
def ping_process_in_rhel_os(
    golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
):
    process_name = "ping"
    return start_and_fetch_processid_on_linux_vm(
        vm=golden_image_vm_object_from_template_multi_rhel_os_multi_storage_scope_class,
        process_name=process_name,
        args="localhost",
    )


@pytest.fixture(scope="class")
def ping_process_in_centos_os(
    golden_image_vm_object_from_template_multi_centos_multi_storage_scope_class,
):
    process_name = "ping"
    return start_and_fetch_processid_on_linux_vm(
        vm=golden_image_vm_object_from_template_multi_centos_multi_storage_scope_class,
        process_name=process_name,
        args="localhost",
    )


@pytest.fixture(scope="session")
def fips_enabled_cluster(workers_utility_pods):
    """
    Check if FIPS is enabled on cluster
    """
    for pod in workers_utility_pods:
        # command output: 0 == fips disabled
        #                 1 == fips enabled
        cluster_fips_status = pod.execute(
            ["bash", "-c", "cat /proc/sys/crypto/fips_enabled"]
        ).strip()
        if int(cluster_fips_status) == 1:
            return True
    return False
