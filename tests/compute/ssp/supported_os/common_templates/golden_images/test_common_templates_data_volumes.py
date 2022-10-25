import pytest
from ocp_resources.datavolume import DataVolume
from ocp_resources.resource import ResourceEditor
from ocp_resources.storage_class import StorageClass
from ocp_resources.template import Template
from pytest_testconfig import config as py_config

from tests.compute.ssp.supported_os.common_templates.golden_images.utils import (
    assert_missing_golden_image_pvc,
)
from tests.os_params import FEDORA_LATEST, FEDORA_LATEST_LABELS, FEDORA_LATEST_OS
from utilities.constants import HOSTPATH_CSI_BASIC, TIMEOUT_8MIN
from utilities.infra import cluster_resource
from utilities.virt import (
    VirtualMachineForTestsFromTemplate,
    running_vm,
    wait_for_vm_interfaces,
)


pytestmark = pytest.mark.post_upgrade


NON_EXISTING_DV_NAME = "non-existing-dv"


class DataVolumeTemplatesVirtualMachine(VirtualMachineForTestsFromTemplate):
    def __init__(
        self,
        name,
        namespace,
        client,
        labels,
        data_source,
        updated_storage_class_params=None,
        updated_source_pvc_name=None,
        use_full_storage_api=False,
    ):
        super().__init__(
            name=name,
            namespace=namespace,
            client=client,
            labels=labels,
            data_source=data_source,
            use_full_storage_api=use_full_storage_api,
        )
        self.data_source = data_source
        self.updated_storage_class_params = updated_storage_class_params
        self.updated_source_pvc_name = updated_source_pvc_name

    def to_dict(self):
        res = super().to_dict()
        vm_datavolumetemplates_storage_spec = res["spec"]["dataVolumeTemplates"][0][
            "spec"
        ]["storage"]
        if self.updated_storage_class_params:
            # Update SC params
            vm_datavolumetemplates_storage_spec[
                "storageClassName"
            ] = self.updated_storage_class_params["storage_class"]
            vm_datavolumetemplates_storage_spec[
                "volumeMode"
            ] = self.updated_storage_class_params["volume_mode"]
            vm_datavolumetemplates_storage_spec["accessModes"] = [
                self.updated_storage_class_params["access_mode"]
            ]

        if self.updated_source_pvc_name:
            ResourceEditor(
                patches={
                    self.data_source: {
                        "spec": {
                            "source": {"pvc": {"name": self.updated_source_pvc_name}}
                        }
                    }
                }
            ).update()

        return res


@pytest.fixture()
def vm_from_golden_image_multi_storage(
    request,
    unprivileged_client,
    namespace,
    golden_image_data_source_multi_storage_scope_function,
):
    with cluster_resource(DataVolumeTemplatesVirtualMachine)(
        name="vm-from-golden-image",
        namespace=namespace.name,
        client=unprivileged_client,
        labels=Template.generate_template_labels(**FEDORA_LATEST_LABELS),
        data_source=golden_image_data_source_multi_storage_scope_function,
        use_full_storage_api=request.param.get("use_full_storage_api"),
    ) as vm:
        running_vm(vm=vm)
        yield vm


@pytest.fixture()
def vm_from_golden_image(
    request,
    unprivileged_client,
    namespace,
    golden_image_data_source_scope_function,
):
    with cluster_resource(DataVolumeTemplatesVirtualMachine)(
        name="vm-from-golden-image-mismatching-sc",
        namespace=namespace.name,
        client=unprivileged_client,
        labels=Template.generate_template_labels(**FEDORA_LATEST_LABELS),
        data_source=golden_image_data_source_scope_function,
        updated_storage_class_params=request.param.get("updated_storage_class_params"),
        updated_source_pvc_name=request.param.get("updated_source_pvc_name"),
    ) as vm:
        if request.param.get("start_vm", True):
            running_vm(vm=vm)
        yield vm


@pytest.mark.parametrize(
    "golden_image_data_volume_multi_storage_scope_function, vm_from_golden_image_multi_storage",
    [
        pytest.param(
            {
                "dv_name": FEDORA_LATEST_OS,
                "image": FEDORA_LATEST["image_path"],
                "dv_size": FEDORA_LATEST["dv_size"],
            },
            {
                "use_full_storage_api": True,
            },
            marks=pytest.mark.polarion("CNV-5582"),
        ),
    ],
    indirect=True,
)
def test_vm_from_golden_image_cluster_default_storage_class(
    updated_default_storage_class_scope_function,
    golden_image_data_volume_multi_storage_scope_function,
    vm_from_golden_image_multi_storage,
):
    vm_from_golden_image_multi_storage.ssh_exec.executor().is_connective()


@pytest.mark.parametrize(
    "data_volume_scope_function, vm_from_template_with_existing_dv",
    [
        pytest.param(
            {
                "dv_name": "dv-fedora",
                "image": FEDORA_LATEST["image_path"],
                "storage_class": py_config["default_storage_class"],
                "dv_size": FEDORA_LATEST["dv_size"],
            },
            {
                "vm_name": "fedora-vm",
                "template_labels": FEDORA_LATEST_LABELS,
            },
            marks=pytest.mark.polarion("CNV-5530"),
        ),
    ],
    indirect=True,
)
def test_vm_with_existing_dv(
    data_volume_scope_function, vm_from_template_with_existing_dv
):
    vm_from_template_with_existing_dv.ssh_exec.executor().is_connective()


@pytest.mark.parametrize(
    "golden_image_data_volume_scope_function, vm_from_golden_image",
    [
        pytest.param(
            {
                "dv_name": FEDORA_LATEST_OS,
                "image": FEDORA_LATEST["image_path"],
                "storage_class": HOSTPATH_CSI_BASIC,
                "dv_size": FEDORA_LATEST["dv_size"],
            },
            {
                "updated_storage_class_params": {
                    "storage_class": StorageClass.Types.NFS,
                    "access_mode": DataVolume.AccessMode.RWX,
                    "volume_mode": DataVolume.VolumeMode.FILE,
                },
            },
            marks=pytest.mark.polarion("CNV-5529"),
        ),
    ],
    indirect=True,
)
@pytest.mark.polarion("CNV-5529")
def test_vm_dv_with_different_sc(
    golden_image_data_volume_scope_function, vm_from_golden_image
):
    # VM cloned PVC storage class is different from the original golden image storage class
    # Using NFS and HPP, as Block <> Filesystem is not supported.
    # TODO: Add OCS - HPP test
    vm_from_golden_image.ssh_exec.executor().is_connective()


@pytest.mark.parametrize(
    "golden_image_data_volume_scope_function, vm_from_golden_image",
    [
        pytest.param(
            {
                "dv_name": "fedora-dv",
                "image": FEDORA_LATEST["image_path"],
                "dv_size": FEDORA_LATEST["dv_size"],
                "storage_class": py_config["default_storage_class"],
            },
            {
                "updated_source_pvc_name": NON_EXISTING_DV_NAME,
                "start_vm": False,
            },
            marks=pytest.mark.polarion("CNV-5528"),
        ),
    ],
    indirect=True,
)
def test_missing_golden_image_pvc(
    admin_client,
    namespace,
    golden_image_data_source_scope_function,
    vm_from_golden_image,
):
    vm_from_golden_image.start()
    assert_missing_golden_image_pvc(
        vm=vm_from_golden_image,
        pvc_name=NON_EXISTING_DV_NAME,
    )

    # Update dataSource spec with the correct name
    ResourceEditor(
        patches={
            golden_image_data_source_scope_function: {
                "spec": {"source": {"pvc": {"name": "fedora-dv"}}}
            }
        }
    ).update()

    vm_from_golden_image.wait_for_ready_status(status=True, timeout=TIMEOUT_8MIN)
    wait_for_vm_interfaces(vmi=vm_from_golden_image.vmi)
