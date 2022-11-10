import pytest
from ocp_resources.datavolume import DataVolume
from ocp_resources.priority_class import PriorityClass
from pytest_testconfig import config as py_config

from tests.os_params import RHEL_LATEST
from tests.storage.utils import get_importer_pod
from utilities.constants import Images
from utilities.infra import cluster_resource
from utilities.storage import get_images_server_url
from utilities.virt import VirtualMachineForTests, fedora_vm_body


@pytest.fixture()
def priority_class(request):
    vm_priority_class_value = request.param.get("vm_priority_class_value")
    dv_priority_class_value = request.param.get("dv_priority_class_value", None)
    with cluster_resource(PriorityClass)(
        name="vm-priority", value=vm_priority_class_value
    ) as vm_priority_class:
        if dv_priority_class_value:
            with cluster_resource(PriorityClass)(
                name="dv-priority", value=dv_priority_class_value
            ) as dv_priority_class:
                yield {
                    "vm_priority_class": vm_priority_class,
                    "dv_priority_class": dv_priority_class,
                }
        else:
            yield {"vm_priority_class": vm_priority_class, "dv_priority_class": None}


@pytest.fixture()
def dv_dict(namespace, priority_class):
    dv = DataVolume(
        source="http",
        name="priority-dv",
        namespace=namespace.name,
        url=f"{get_images_server_url(schema='http')}{RHEL_LATEST['image_path']}",
        size=RHEL_LATEST["dv_size"],
        storage_class=py_config["default_storage_class"],
        volume_mode=py_config["default_volume_mode"],
        access_modes=py_config["default_access_mode"],
    )
    dv.to_dict()
    dv_priority_class = priority_class["dv_priority_class"]
    if dv_priority_class:
        dv.res["spec"]["priorityClassName"] = dv_priority_class.name
    return dv.res


@pytest.fixture()
def vm_with_priority_class(
    namespace,
    dv_dict,
    priority_class,
):
    vm_priority_class = priority_class["vm_priority_class"]
    vm_name = "priority-vm"
    with cluster_resource(VirtualMachineForTests)(
        name="priority-vm",
        namespace=namespace.name,
        data_volume_template={
            "metadata": dv_dict["metadata"],
            "spec": dv_dict["spec"],
        },
        memory_requests=Images.Rhel.DEFAULT_MEMORY_SIZE,
        priority_class_name=vm_priority_class.name,
        body=fedora_vm_body(name=vm_name),
        running=True,
    ) as vm:
        yield vm


@pytest.fixture()
def importer_pod(admin_client, namespace):
    return get_importer_pod(dyn_client=admin_client, namespace=namespace.name)


@pytest.mark.sno
@pytest.mark.parametrize(
    "priority_class",
    [
        pytest.param(
            {
                "vm_priority_class_value": 1000000,
            },
            marks=(pytest.mark.polarion("CNV-6808")),
        ),
    ],
    indirect=True,
)
def test_dv_template_has_the_same_priority_as_vm_when_not_specified(
    priority_class,
    vm_with_priority_class,
    importer_pod,
):
    assert (
        importer_pod.instance.spec.priority == priority_class["vm_priority_class"].value
    )


@pytest.mark.sno
@pytest.mark.parametrize(
    "priority_class",
    [
        pytest.param(
            {
                "vm_priority_class_value": 2000000,
                "dv_priority_class_value": 1000000,
            },
            marks=(pytest.mark.polarion("CNV-6811")),
        ),
    ],
    indirect=True,
)
def test_dv_template_has_the_different_priority_as_vm_when_specify(
    priority_class, vm_with_priority_class, importer_pod
):
    assert (
        importer_pod.instance.spec.priority != priority_class["vm_priority_class"].value
    )
