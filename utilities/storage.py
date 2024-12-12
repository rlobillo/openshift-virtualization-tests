import logging
import math
import os
import shlex
import ssl
from contextlib import contextmanager

import kubernetes
import requests
from ocp_resources.cdi import CDI
from ocp_resources.cdi_config import CDIConfig
from ocp_resources.data_source import DataSource
from ocp_resources.datavolume import DataVolume
from ocp_resources.deployment import Deployment
from ocp_resources.persistent_volume_claim import PersistentVolumeClaim
from ocp_resources.pod import Pod
from ocp_resources.resource import NamespacedResource, ResourceEditor, get_client
from ocp_resources.storage_class import StorageClass
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from ocp_resources.volume_snapshot_class import VolumeSnapshotClass
from ocp_utilities.infra import cluster_resource
from openshift.dynamic.exceptions import NotFoundError
from pyhelper_utils.shell import run_ssh_commands
from pytest_testconfig import config as py_config

import utilities.infra
from utilities import console
from utilities.constants import (
    CNV_TEST_SERVICE_ACCOUNT,
    HOTPLUG_DISK_SERIAL,
    HTTP_OK,
    OS_FLAVOR_WINDOWS,
    TIMEOUT_2MIN,
    TIMEOUT_3MIN,
    TIMEOUT_5MIN,
    TIMEOUT_20SEC,
    TIMEOUT_30MIN,
    TIMEOUT_60MIN,
    Images,
)
from utilities.exceptions import UrlNotFoundError


SECURITY_CONTEXT = "securityContext"
HOTPLUG_VOLUME = "hotplugVolume"
DATA_IMPORT_CRON_SUFFIX = "-image-cron"
RESOURCE_MANAGED_BY_DATA_IMPORT_CRON_LABEL = (
    f"{NamespacedResource.ApiGroup.CDI_KUBEVIRT_IO}/dataImportCron"
)
HOSTPATH_CSI = "hostpath-csi"
HPP_CSI = "hpp-csi"


LOGGER = logging.getLogger(__name__)


def dv_reached_wffc_phase(dv):
    try:
        dv.wait_for_status(
            status=StorageClass.VolumeBindingMode.WaitForFirstConsumer,
            timeout=TIMEOUT_20SEC,
        )
        return True
    except TimeoutExpiredError:
        # We are not guaranteed to get to this status, can fail earlier
        LOGGER.warning(
            f"Status {StorageClass.VolumeBindingMode.WaitForFirstConsumer} wasn't reached,"
            " failure occurred prior to consuming of PVC"
        )


def create_dummy_first_consumer_pod(
    volume_mode=DataVolume.VolumeMode.FILE, dv=None, pvc=None
):
    """
    Create a dummy pod that will become the PVCs first consumer
    Triggers start of CDI worker pod

    To consume PVCs that are not backed by DVs, just pass in pvc param
    Otherwise, it is needed to pass in dv
    """
    if not (pvc or dv):
        raise ValueError("Exactly one of the args: (dv,pvc) must be passed")
    if pvc or dv_reached_wffc_phase(dv=dv):
        pvc = pvc or dv.pvc
        with PodWithPVC(
            namespace=pvc.namespace,
            name=f"first-consumer-{pvc.name}",
            pvc_name=pvc.name,
            volume_mode=volume_mode,
        ) as pod:
            LOGGER.info(
                f"Created dummy pod {pod.name} to be the first consumer of the PVC, "
                "this triggers the start of CDI worker pods in case the PVC is backed by DV"
            )
            pvc.wait_for_status(status=pvc.Status.BOUND)


@contextmanager
def create_dv(
    dv_name,
    namespace,
    storage_class,
    volume_mode=None,
    url=None,
    source="http",
    content_type=DataVolume.ContentType.KUBEVIRT,
    size="5Gi",
    secret=None,
    cert_configmap=None,
    hostpath_node=None,
    access_modes=None,
    client=None,
    source_pvc=None,
    source_namespace=None,
    multus_annotation=None,
    teardown=True,
    consume_wffc=True,
    bind_immediate=None,
    preallocation=None,
    api_name="storage",
):
    artifactory_secret = None
    cert_created = None
    if source in ("http", "https"):
        if not utilities.infra.url_excluded_from_validation(url):
            # Make sure URL exists
            validate_file_exists_in_url(url=url)
        if not secret:
            secret = utilities.infra.get_artifactory_secret(namespace=namespace)
            artifactory_secret = secret
        if not cert_configmap:
            cert_created = utilities.infra.get_artifactory_config_map(
                namespace=namespace
            )
            cert_configmap = cert_created.name

    with cluster_resource(DataVolume)(
        source=source,
        name=dv_name,
        namespace=namespace,
        url=url,
        content_type=content_type,
        size=size,
        storage_class=storage_class,
        cert_configmap=cert_configmap,
        volume_mode=volume_mode,
        hostpath_node=hostpath_node,
        access_modes=access_modes,
        secret=secret,
        client=client,
        source_pvc=source_pvc,
        source_namespace=source_namespace,
        bind_immediate_annotation=bind_immediate,
        multus_annotation=multus_annotation,
        teardown=teardown,
        preallocation=preallocation,
        privileged_client=get_client(),
        api_name=api_name,
    ) as dv:
        if sc_volume_binding_mode_is_wffc(sc=storage_class) and consume_wffc:
            create_dummy_first_consumer_pod(dv=dv)
        yield dv
    utilities.infra.cleanup_artifactory_secret_and_config_map(
        artifactory_secret=artifactory_secret, artifactory_config_map=cert_created
    )


def data_volume(
    namespace,
    storage_class_matrix=None,
    storage_class=None,
    schedulable_nodes=None,
    request=None,
    os_matrix=None,
    check_dv_exists=False,
    admin_client=None,
    bind_immediate=None,
):
    """
    DV creation using create_dv.

    Args:
        namespace (:obj: `Namespace`): namespace resource
        storage_class_matrix (dict): Contains current storage_class_matrix attributes
        storage_class (str): Storage class name
        schedulable_nodes (list): List of schedulable nodes objects
        os_matrix (dict): Contains current os_matrix attributes
        check_dv_exists (bool): Skip DV creation if DV exists. Used for golden images. IF the DV exists in golden images
        namespace, it can be used for cloning.
        bind_immediate (bool): if True, cdi.kubevirt.io/storage.bind.immediate.requested annotation

    Yields:
        obj `DataVolume`: DV resource

    """
    if not storage_class_matrix:
        storage_class_matrix = get_storage_class_dict_from_matrix(
            storage_class=storage_class
        )

    storage_class = [*storage_class_matrix][0]
    # Save with a different name to avoid confusing.

    params_dict = request.param if request else {}

    # Set DV attributes
    # DV name is the only mandatory value
    # Values can be extracted from request.param or from
    # rhel_os_matrix or windows_os_matrix (passed as os_matrix)
    source = params_dict.get("source", "http")
    consume_wffc = params_dict.get("consume_wffc", True)

    # DV namespace may not be in the same namespace as the originating test
    # If a namespace is passes in request.param, use it instead of the test's namespace
    dv_namespace = params_dict.get("dv_namespace", namespace.name)

    if os_matrix:
        os_matrix_key = [*os_matrix][0]
        image = os_matrix[os_matrix_key]["image_path"]
        dv_name = os_matrix_key
        dv_size = os_matrix[os_matrix_key].get("dv_size")
    else:
        image = params_dict.get("image", "")
        dv_name = params_dict.get("dv_name").replace(".", "-").lower()
        dv_size = params_dict.get("dv_size")

    # Don't need URL for DVs that are not http
    url = f"{get_images_server_url()}{image}" if source == "http" else None

    is_golden_image = False
    # For golden images; images are created once per module in
    # golden images namepace and cloned when using common templates.
    # If the DV exists, yield the DV else create a new one in
    # golden images namespace
    # If SC is HPP, cdi.kubevirt.io/storage.bind.immediate.requested annotation
    # should be used to avoid wffc
    if check_dv_exists:
        consume_wffc = False
        bind_immediate = True
        is_golden_image = True
        try:
            golden_image = list(
                DataVolume.get(
                    dyn_client=admin_client, name=dv_name, namespace=dv_namespace
                )
            )
            yield golden_image[0]
        except NotFoundError:
            LOGGER.warning(f"Golden image {dv_name} not found; DV will be created.")

    # In hpp, volume must reside on the same worker as the VM
    # This is not needed for golden image PVC
    hostpath_node = (
        schedulable_nodes[0].name
        if (
            sc_is_hpp_with_immediate_volume_binding(sc=storage_class)
            and not is_golden_image
        )
        else None
    )

    dv_kwargs = {
        "dv_name": dv_name,
        "namespace": dv_namespace,
        "source": source,
        "size": dv_size,
        "storage_class": params_dict.get("storage_class", storage_class),
        "access_modes": params_dict.get("access_modes"),
        "volume_mode": params_dict.get("volume_mode"),
        "content_type": DataVolume.ContentType.KUBEVIRT,
        "hostpath_node": hostpath_node,
        "consume_wffc": consume_wffc,
        "bind_immediate": bind_immediate,
        "preallocation": params_dict.get("preallocation", None),
        "url": url,
    }
    if params_dict.get("cert_configmap"):
        dv_kwargs["cert_configmap"] = params_dict.get("cert_configmap")
    # Create dv
    with create_dv(**{k: v for k, v in dv_kwargs.items() if v is not None}) as dv:
        if params_dict.get("wait", True):
            if source == "upload":
                dv.wait_for_condition(
                    condition=DataVolume.Condition.Type.BOUND,
                    status=DataVolume.Condition.Status.TRUE,
                    timeout=TIMEOUT_5MIN,
                )
                dv.wait_for_status(
                    status=DataVolume.Status.UPLOAD_READY, timeout=TIMEOUT_3MIN
                )
            else:
                if (
                    not consume_wffc
                    and sc_volume_binding_mode_is_wffc(sc=storage_class)
                    and check_cdi_feature_gate_enabled(
                        feature="HonorWaitForFirstConsumer"
                    )
                    and not bind_immediate
                ):
                    # In the case of WFFC Storage Class && caller asking to NOT consume && WFFC feature gate enabled
                    # and bind_immediate is False (i.e bind_immediate annotation will be added, import will not wait
                    # first consumer)
                    # We will hand out a DV that has nothing on it, just waiting to be further consumed by kubevirt
                    # It will be in a new status 'WaitForFirstConsumer' (this is how the caller wanted it)
                    dv.wait_for_status(
                        status=StorageClass.VolumeBindingMode.WaitForFirstConsumer,
                        timeout=10,
                    )
                else:
                    dv.wait_for_dv_success(
                        timeout=TIMEOUT_60MIN
                        if OS_FLAVOR_WINDOWS in image
                        else TIMEOUT_30MIN
                    )
        yield dv


def downloaded_image(remote_name, local_name):
    """
    Download image to local tmpdir path
    """
    artifactory_header = utilities.infra.get_artifactory_header()
    url = f"{get_images_server_url()}{remote_name}"
    resp = requests.head(
        url=url,
        headers=artifactory_header,
        verify=False,
        allow_redirects=True,
    )
    assert (
        resp.status_code == requests.codes.ok
    ), f"Unable to connect to {url} with error: {resp}."
    LOGGER.info(f"Download {url} to {local_name}")
    with requests.get(
        url=url, headers=artifactory_header, verify=False, stream=True
    ) as created_request:
        created_request.raise_for_status()
        with open(local_name, "wb") as file_downloaded:
            for chunk in created_request.iter_content(chunk_size=8192):
                file_downloaded.write(chunk)
    try:
        assert os.path.isfile(local_name)
    except FileNotFoundError as err:
        LOGGER.error(err)
        raise


def get_storage_class_dict_from_matrix(storage_class):
    storages = py_config["system_storage_class_matrix"]
    matching_storage_classes = [sc for sc in storages if [*sc][0] == storage_class]
    if not matching_storage_classes:
        raise ValueError(f"{storage_class} not found in {storages}")
    return matching_storage_classes[0]


def sc_is_hpp_with_immediate_volume_binding(sc):
    return (
        sc == "hostpath-provisioner"
        and StorageClass(name=sc).instance["volumeBindingMode"]
        == StorageClass.VolumeBindingMode.Immediate
    )


def sc_volume_binding_mode_is_wffc(sc):
    return (
        StorageClass(name=sc).instance["volumeBindingMode"]
        == StorageClass.VolumeBindingMode.WaitForFirstConsumer
    )


def check_cdi_feature_gate_enabled(feature):
    return feature in CDIConfig(name="config").instance.to_dict().get("spec", {}).get(
        "featureGates", []
    )


@contextmanager
def virtctl_volume(
    action,
    namespace,
    vm_name,
    volume_name,
    serial=None,
    persist=None,
):
    operation = {"add": "addvolume"}
    volume_operation = operation[action]
    command = [
        f"{volume_operation}",
        f"{vm_name}",
        f"--volume-name={volume_name}",
    ]
    if serial:
        command.append(f"--serial={serial}")
    if persist:
        command.append("--persist")

    yield utilities.infra.run_virtctl_command(command=command, namespace=namespace)


def virtctl_memory_dump(
    namespace,
    action,
    vm_name,
    claim_name=None,
    storage_class=None,
    create_claim=None,
):
    """
    Dump the memory of a running VM to a PVC.

    Args:
        namespace (:obj: `Namespace`): namespace resource
        action (str): get - trigger memory dump; remove - disassociation of the memory dump pvc
        vm_name (str): virtual machine name
        claim_name (str): PVC name to contain the memory dump
        storage_class (str): Storage class for the memory dump PVC
        create_claim (bool): If true, create new PVC that will contain memory dump
    """
    command = [
        "memory-dump",
        action,
        vm_name,
    ]
    if claim_name:
        command.append(f"--claim-name={claim_name}")
    if create_claim:
        command.append("--create-claim")
    if storage_class:
        command.append(f"--storage-class={storage_class}")

    return utilities.infra.run_virtctl_command(command=command, namespace=namespace)


@contextmanager
def virtctl_upload_dv(
    namespace,
    name,
    image_path,
    size,
    pvc=False,
    storage_class=None,
    volume_mode=None,
    access_mode=None,
    uploadproxy_url=None,
    wait_secs=None,
    insecure=False,
    no_create=False,
    consume_wffc=True,
    cleanup=True,
):
    command = [
        "image-upload",
        f"{'dv' if not pvc else pvc}",
        f"{name}",
        f"--image-path={image_path}",
        f"--size={size}",
    ]
    resource_to_cleanup = (
        PersistentVolumeClaim(namespace=namespace, name=name)
        if pvc
        else DataVolume(namespace=namespace, name=name)
    )
    if pvc:
        command[1] = "pvc"
    if storage_class:
        if not (
            volume_mode and access_mode
        ):  # In case either one of them is missing, must fetch missing mode/s from matrix
            storage_class_dict = get_storage_class_dict_from_matrix(
                storage_class=storage_class
            )
            storage_class = [*storage_class_dict][0]
        # There is still an option that one mode was passed by caller, will use the passed value
        volume_mode = volume_mode or storage_class_dict[storage_class]["volume_mode"]
        access_mode = access_mode or storage_class_dict[storage_class]["access_mode"]
        command.append(f"--storage-class={storage_class}")
    if access_mode:
        command.append(f"--access-mode={access_mode}")
    if uploadproxy_url:
        command.append(f"--uploadproxy-url={uploadproxy_url}")
    if wait_secs:
        command.append(f"--wait-secs={wait_secs}")
    if insecure:
        command.append("--insecure")
    if volume_mode == "Block":
        command.append("--block-volume")
    if no_create:
        command.append("--no-create")
    if (
        sc_volume_binding_mode_is_wffc(sc=storage_class)
        and consume_wffc
        and not no_create
    ):
        command.append("--force-bind")

    yield utilities.infra.run_virtctl_command(command=command, namespace=namespace)

    if cleanup:
        resource_to_cleanup.clean_up()


def check_upload_virtctl_result(
    result,
    expected_success=True,
    expected_output="Processing completed successfully",
    assert_message=None,
):
    LOGGER.info("Check status and output of virtctl")
    status, out, err = result
    assert_message = assert_message or err
    if expected_success:
        assert status, assert_message
        assert expected_output in out, out
    else:
        assert not status, assert_message
        assert expected_output in err, err


class HttpDeployment(Deployment):
    def to_dict(self):
        super().to_dict()
        self.res.update(
            {
                "spec": {
                    "replicas": 1,
                    "selector": {"matchLabels": {"name": "internal-http"}},
                    "template": {
                        "metadata": {
                            "labels": {
                                "name": "internal-http",
                                "cdi.kubevirt.io/testing": "",
                            }
                        },
                        "spec": {
                            "terminationGracePeriodSeconds": 0,
                            "containers": [
                                {
                                    "name": "http",
                                    "image": "quay.io/openshift-cnv/qe-cnv-tests-internal-http:v1.0.0",
                                    "imagePullPolicy": "Always",
                                    "command": ["/usr/sbin/nginx"],
                                    "readinessProbe": {
                                        "httpGet": {"path": "/", "port": 80},
                                        "initialDelaySeconds": 20,
                                        "periodSeconds": 20,
                                    },
                                    SECURITY_CONTEXT: {"privileged": True},
                                    "livenessProbe": {
                                        "httpGet": {"path": "/", "port": 80},
                                        "initialDelaySeconds": 20,
                                        "periodSeconds": 20,
                                    },
                                }
                            ],
                            "serviceAccount": CNV_TEST_SERVICE_ACCOUNT,
                            "serviceAccountName": CNV_TEST_SERVICE_ACCOUNT,
                        },
                    },
                }
            }
        )


class ErrorMsg:
    """
    error messages that might show in pod containers
    """

    EXIT_STATUS_2 = (
        "Unable to process data: "
        "Unable to transfer source data to target directory: unable to untar files from endpoint: exit status 2"
    )
    CERTIFICATE_SIGNED_UNKNOWN_AUTHORITY = "certificate signed by unknown authority"
    DISK_IMAGE_IN_CONTAINER_NOT_FOUND = (
        "Unable to process data: Unable to transfer source data to scratch space: "
        "Failed to read registry image: Failed to find VM disk image file in the container image"
    )
    DATA_VOLUME_TOO_SMALL = "DataVolume too small to contain image"
    LARGER_PVC_REQUIRED = "A larger PVC is required"
    LARGER_PVC_REQUIRED_CLONE = (
        "target resources requests storage size is smaller than the source"
    )
    INVALID_FORMAT_FOR_QCOW = "Unable to process data: Invalid format qcow for image "
    COULD_NOT_OPEN_SIZE_TOO_BIG = "Unable to process data: qemu-img: Could not open '/data/disk.img': L1 size too big"
    REQUESTED_RANGE_NOT_SATISFIABLE = (
        "Unable to process data: qemu-img: curl: The requested URL returned error: "
        "416 Requested Range Not Satisfiable"
    )
    CANNOT_CREATE_RESOURCE = r".*cannot create resource.*|.*has insufficient permissions in clone source namespace.*"
    CANNOT_DELETE_RESOURCE = r".*cannot delete resource.*|.*has insufficient permissions in clone source namespace.*"


class PodWithPVC(Pod):
    def __init__(self, name, namespace, pvc_name, volume_mode, teardown=True):
        super().__init__(name=name, namespace=namespace, teardown=teardown)
        self._pvc_name = pvc_name
        self._volume_mode = volume_mode

    def to_dict(self):
        super().to_dict()

        if self._volume_mode == DataVolume.VolumeMode.BLOCK:
            volume_path = {
                "volumeDevices": [
                    {"devicePath": "/pvc/disk.img", "name": self._pvc_name}
                ]
            }
        else:
            volume_path = {
                "volumeMounts": [{"mountPath": "/pvc", "name": self._pvc_name}]
            }

        self.res.update(
            {
                "spec": {
                    SECURITY_CONTEXT: {
                        "seccompProfile": {"type": "RuntimeDefault"},
                        "runAsNonRoot": True,
                        "runAsUser": 1000,
                        "fsGroup": 107,
                    },
                    "containers": [
                        {
                            "name": "runner",
                            "image": "quay.io/openshift-cnv/qe-cnv-tests-net-util-container:latest",
                            "command": [
                                "/bin/bash",
                                "-c",
                                "echo ok > /tmp/healthy && sleep INF",
                            ],
                            SECURITY_CONTEXT: {
                                "allowPrivilegeEscalation": False,
                                "capabilities": {"drop": ["ALL"]},
                            },
                            **volume_path,
                        }
                    ],
                    "volumes": [
                        {
                            "name": self._pvc_name,
                            "persistentVolumeClaim": {"claimName": self._pvc_name},
                        }
                    ],
                }
            }
        )

    def delete(self, wait=False, timeout=TIMEOUT_3MIN, body=None):
        super().delete(
            wait=wait,
            timeout=timeout,
            body=kubernetes.client.V1DeleteOptions(grace_period_seconds=0),
        )


def data_volume_template_dict(
    target_dv_name,
    target_dv_namespace,
    source_dv,
    volume_mode=None,
    size=None,
    storage_class=None,
):
    source_dv_pvc_spec = source_dv.pvc.instance.spec
    dv = DataVolume(
        name=target_dv_name,
        namespace=target_dv_namespace,
        source="pvc",
        storage_class=storage_class or source_dv_pvc_spec.storageClassName,
        volume_mode=volume_mode or source_dv_pvc_spec.volumeMode,
        access_modes=",".join(source_dv_pvc_spec.accessModes),
        size=size or source_dv.size,
        source_pvc=source_dv.name,
        source_namespace=source_dv.namespace,
        api_name=source_dv.api_name,
    )
    dv.to_dict()
    return dv.res


def get_images_server_url(schema="https"):
    """
    Fetch http/s server url from config and return if available.

    Args:
        schema (str): http or https.

    Returns:
        str: Server URL.

    Raises:
        URLError: If server is not accessible.
    """
    server = py_config["servers"][f"{schema}_server"]
    if py_config.get("check_http_server_connectivity", "true").lower() == "false":
        LOGGER.warning(f"Skip {server} connectivity check")
        return server

    myssl = None
    if schema == "https":
        myssl = ssl.create_default_context()
        myssl.check_hostname = False
        myssl.verify_mode = ssl.CERT_NONE

    LOGGER.info(f"Testing connectivity to {server} {schema.upper()} server")
    resp = requests.get(
        url=server, headers=utilities.infra.get_artifactory_header(), verify=False
    )
    assert resp.status_code == requests.codes.ok, (
        f"Unable to connect to test image server: {server} "
        f"{schema.upper()}, with error code: {resp.status_code}, error: {resp.text}"
    )

    return server


def overhead_size_for_dv(image_size, overhead_value):
    """
    Calculate the size of the dv to include overhead and rounds up

    DV creation can be with a fraction only if the corresponding  mebibyte is an integer
    """
    dv_size = image_size / (1 - overhead_value) * 1024
    return f"{math.ceil(dv_size)}Mi"


def cdi_feature_gate_list_with_added_feature(feature):
    return [
        *CDIConfig(name="config")
        .instance.to_dict()
        .get("spec", {})
        .get("featureGates", []),
        feature,
    ]


def wait_for_default_sc_in_cdiconfig(cdi_config, sc):
    """
    Wait for the default storage class to propagate to CDIConfig as the storage class for scratch space
    """
    samples = TimeoutSampler(
        wait_timeout=20,
        sleep=1,
        func=lambda: cdi_config.scratch_space_storage_class_from_status == sc,
    )
    for sample in samples:
        if sample:
            return


def get_hyperconverged_cdi(admin_client):
    for cdi in CDI.get(
        dyn_client=admin_client,
        name="cdi-kubevirt-hyperconverged",
    ):
        return cdi


def write_file(vm, filename, content):
    """Start VM if not running, write a file in the VM and stop the VM"""
    if not vm.instance.spec.running:
        vm.start(wait=True)
    with console.Cirros(vm=vm) as vm_console:
        vm_console.sendline(f"echo '{content}' >> {filename}")
    vm.stop(wait=True)


def run_command_on_cirros_vm_and_check_output(vm, command, expected_result):
    with console.Cirros(vm=vm) as vm_console:
        vm_console.sendline(command)
        vm_console.expect(expected_result, timeout=20)


def assert_disk_serial(vm, command=shlex.split("sudo ls /dev/disk/by-id")):
    assert (
        HOTPLUG_DISK_SERIAL in run_ssh_commands(host=vm.ssh_exec, commands=command)[0]
    ), f"hotplug disk serial id {HOTPLUG_DISK_SERIAL} is not in VM"


def assert_hotplugvolume_nonexist_optional_restart(vm, restart=False):
    if restart:
        vm.restart(wait=True)
    volume_status = vm.vmi.instance.status.volumeStatus[0]
    assert (
        HOTPLUG_VOLUME not in volume_status
    ), f"{HOTPLUG_VOLUME} in {volume_status}, hotplug disk should become a regular disk for VM after restart"


def wait_for_vm_volume_ready(vm):
    sampler = TimeoutSampler(
        wait_timeout=TIMEOUT_2MIN,
        sleep=1,
        func=lambda: vm.vmi.instance,
    )
    for sample in sampler:
        if sample.status.volumeStatus[0]["reason"] == "VolumeReady":
            return


def generate_data_source_dict(dv):
    return {"pvc": {"name": dv.name, "namespace": dv.namespace}}


def create_or_update_data_source(admin_client, dv):
    """
    Create or updates a data source referencing a provided DV.

    As dataSources are automatically created with CNV deployment for golden images support, they can be re-used.
    If a dataSource already exists (with the same name as the target dv), it will be updated.
    Otherwise a new dataSource will be created.

    Args:
        admin_client (client)
        dv (DataVolume): which will be referenced in the data source

    Yields:
        DataSource object
    """
    target_name = dv.name
    target_namespaces = dv.namespace
    try:
        for data_source in DataSource.get(
            dyn_client=admin_client, name=target_name, namespace=target_namespaces
        ):
            LOGGER.info(f"Updating existing dataSource {data_source.name}")
            with ResourceEditor(
                patches={data_source: generate_data_source_dict(dv=dv)}
            ):
                yield data_source
    except NotFoundError:
        with cluster_resource(DataSource)(
            name=target_name,
            namespace=target_namespaces,
            client=admin_client,
            source=generate_data_source_dict(dv=dv),
        ) as data_source:
            yield data_source


class HppCsiStorageClass(StorageClass):
    class Name:
        # Without explicit storage pool, used with the Legacy HPP CR
        HOSTPATH_CSI_LEGACY = f"{HOSTPATH_CSI}-legacy"
        HOSTPATH_CSI_BASIC = f"{HOSTPATH_CSI}-basic"  # Part of fresh deployment
        HOSTPATH_CSI_PVC_BLOCK = f"{HOSTPATH_CSI}-pvc-block"  # Part of fresh deployment
        HOSTPATH_CSI_PVC_TEMPLATE_OCS_BLOCK = f"{HOSTPATH_CSI}-pvc-template-ocs-block"
        HOSTPATH_CSI_PVC_TEMPLATE_OCS_FS = f"{HOSTPATH_CSI}-pvc-template-ocs-fs"
        HOSTPATH_CSI_PVC_TEMPLATE_LSO = f"{HOSTPATH_CSI}-pvc-template-lso"

    class StoragePool:
        HOSTPATH_CSI_BASIC = f"{HPP_CSI}-local-basic"
        HOSTPATH_CSI_PVC_BLOCK = f"{HPP_CSI}-pvc-block"
        HOSTPATH_CSI_PVC_TEMPLATE_OCS_BLOCK = f"{HPP_CSI}-pvc-template-ocs-block"
        HOSTPATH_CSI_PVC_TEMPLATE_OCS_FS = f"{HPP_CSI}-pvc-template-ocs-fs"
        HOSTPATH_CSI_PVC_TEMPLATE_LSO = f"{HPP_CSI}-pvc-template-lso"

    def __init__(self, name, storage_pool=None, teardown=True):
        super().__init__(name=name, teardown=teardown)
        self._storage_pool = storage_pool

    def to_dict(self):
        super().to_dict()
        self.res.update(
            {
                "provisioner": StorageClass.Provisioner.HOSTPATH_CSI,
                "reclaimPolicy": "Delete",
                "volumeBindingMode": StorageClass.VolumeBindingMode.WaitForFirstConsumer,
            }
        )
        if self._storage_pool:
            self.res.update(
                {
                    "parameters": {"storagePool": self._storage_pool},
                }
            )


def default_storage_class(client):
    default_sc_list = [
        sc
        for sc in StorageClass.get(dyn_client=client)
        if sc.instance.metadata.get("annotations", {}).get(
            StorageClass.Annotations.IS_DEFAULT_CLASS
        )
        == "true"
    ]
    if default_sc_list:
        return default_sc_list[0]
    raise ValueError("No default storage class defined")


def is_snapshot_supported_by_sc(sc_name, client):
    sc_instance = StorageClass(client=client, name=sc_name).instance
    for vsc in VolumeSnapshotClass.get(dyn_client=client):
        if vsc.instance.get("driver") == sc_instance.get("provisioner"):
            return True
    return False


def create_cirros_dv_for_snapshot_dict(
    name, namespace, storage_class, artifactory_secret, artifactory_config_map
):
    dv = cluster_resource(DataVolume)(
        api_name="storage",
        name=f"dv-{name}",
        namespace=namespace,
        source="http",
        url=utilities.infra.get_http_image_url(
            image_directory=Images.Cirros.DIR, image_name=Images.Cirros.QCOW2_IMG
        ),
        storage_class=storage_class,
        size=Images.Cirros.DEFAULT_DV_SIZE,
        secret=artifactory_secret,
        cert_configmap=artifactory_config_map.name,
    )
    dv.to_dict()
    return dv.res


class OCSVirtualizationStorageClass(StorageClass):
    def __init__(self, name, teardown=False):
        super().__init__(name=name, teardown=teardown)

    def to_dict(self):
        super().to_dict()
        self.res.update(
            {
                "provisioner": StorageClass.Provisioner.CEPH_RBD,
                "reclaimPolicy": "Delete",
                "volumeBindingMode": StorageClass.VolumeBindingMode.Immediate,
                "allowVolumeExpansion": True,
                "parameters": {
                    "clusterID": "openshift-storage",
                    "csi.storage.k8s.io/controller-expand-secret-name": "rook-csi-rbd-provisioner",
                    "csi.storage.k8s.io/controller-expand-secret-namespace": "openshift-storage",
                    "csi.storage.k8s.io/fstype": "ext4",
                    "csi.storage.k8s.io/node-stage-secret-name": "rook-csi-rbd-node",
                    "csi.storage.k8s.io/node-stage-secret-namespace": "openshift-storage",
                    "csi.storage.k8s.io/provisioner-secret-name": "rook-csi-rbd-provisioner",
                    "csi.storage.k8s.io/provisioner-secret-namespace": "openshift-storage",
                    "imageFeatures": "layering,deep-flatten,exclusive-lock,object-map,fast-diff",
                    "imageFormat": "2",
                    "mapOptions": "krbd:rxbounce",
                    "mounter": "rbd",
                    "pool": "ocs-storagecluster-cephblockpool",
                },
            }
        )


def validate_file_exists_in_url(url):
    response = requests.head(
        url=url, headers=utilities.infra.get_artifactory_header(), verify=False
    )
    if response.status_code != HTTP_OK:
        raise UrlNotFoundError(url_request=response)
