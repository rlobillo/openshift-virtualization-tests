import io
import ipaddress
import json
import logging
import os
import re
import shlex
from collections import defaultdict
from contextlib import contextmanager
from json import JSONDecodeError
from subprocess import run

import jinja2
import pexpect
import requests
import yaml
from benedict import benedict
from kubernetes.client import ApiException
from ocp_resources.datavolume import DataVolume
from ocp_resources.kubevirt import KubeVirt
from ocp_resources.node import Node
from ocp_resources.pod import Pod
from ocp_resources.pod_disruption_budget import PodDisruptionBudget
from ocp_resources.resource import Resource, ResourceEditor, get_client
from ocp_resources.route import Route
from ocp_resources.secret import Secret
from ocp_resources.service import Service
from ocp_resources.service_account import ServiceAccount
from ocp_resources.storage_profile import StorageProfile
from ocp_resources.template import Template
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from ocp_resources.virtual_machine import VirtualMachine
from ocp_resources.virtual_machine_instance_migration import (
    VirtualMachineInstanceMigration,
)
from ocp_utilities.exceptions import CommandExecFailed
from pyhelper_utils.shell import run_command
from pytest_testconfig import config as py_config
from rrmngmnt import Host, ssh, user

import utilities.infra
import utilities.storage
from utilities.constants import (
    CLOUD_INIT_DISK_NAME,
    CLOUD_INIT_NO_CLOUD,
    CLOUND_INIT_CONFIG_DRIVE,
    CNV_VM_SSH_KEY_PATH,
    DATA_SOURCE_NAME,
    DATA_SOURCE_NAMESPACE,
    DEFAULT_KUBEVIRT_CONDITIONS,
    EVICTION_STRATEGY,
    IP_FAMILY_POLICY_PREFER_DUAL_STACK,
    LIVE_MIGRATE,
    OS_FLAVOR_CIRROS,
    OS_FLAVOR_FEDORA,
    OS_FLAVOR_WINDOWS,
    OS_LOGIN_PARAMS,
    ROOTDISK,
    SSH_PORT_22,
    TIMEOUT_1MIN,
    TIMEOUT_2MIN,
    TIMEOUT_3MIN,
    TIMEOUT_4MIN,
    TIMEOUT_5SEC,
    TIMEOUT_6MIN,
    TIMEOUT_8MIN,
    TIMEOUT_10MIN,
    TIMEOUT_12MIN,
    TIMEOUT_25MIN,
    TIMEOUT_30MIN,
    WORKERS_TYPE,
    Images,
)
from utilities.hco import get_hco_namespace, wait_for_hco_conditions


LOGGER = logging.getLogger(__name__)

K8S_TAINT = "node.kubernetes.io/unschedulable"
NO_SCHEDULE = "NoSchedule"
CIRROS_IMAGE = "kubevirt/cirros-container-disk-demo:latest"
FLAVORS_EXCLUDED_FROM_CLOUD_INIT = (OS_FLAVOR_WINDOWS, OS_FLAVOR_CIRROS)


def wait_for_guest_agent(vmi, timeout=TIMEOUT_12MIN):
    LOGGER.info(f"Wait until guest agent is active on {vmi.name}")

    sampler = TimeoutSampler(wait_timeout=timeout, sleep=1, func=lambda: vmi.instance)
    try:
        for sample in sampler:
            agent_status = [
                condition
                for condition in sample.get("status", {}).get("conditions", {})
                if condition.get("type") == "AgentConnected"
                and condition.get("status") == "True"
            ]
            if agent_status:
                return True

    except TimeoutExpiredError:
        LOGGER.error(f"Guest agent is not installed or not active on {vmi.name}")
        raise


def wait_for_vm_interfaces(vmi, timeout=TIMEOUT_12MIN):
    """
    Wait until guest agent report VMI network interfaces.

    Args:
        vmi (VirtualMachineInstance): VMI object.
        timeout (int): Maximum time to wait for interfaces status

    Returns:
        bool: True if agent report VMI interfaces.

    Raises:
        TimeoutExpiredError: After timeout reached.
    """
    # Waiting for guest agent connection before checking guest agent interfaces report
    if wait_for_guest_agent(vmi=vmi, timeout=timeout):
        LOGGER.info(f"Wait for {vmi.name} network interfaces")
        sampler = TimeoutSampler(
            wait_timeout=timeout, sleep=1, func=lambda: vmi.instance
        )
        for sample in sampler:
            interfaces = sample.get("status", {}).get("interfaces", [])
            active_interfaces = [
                interface for interface in interfaces if interface.get("interfaceName")
            ]
            if len(active_interfaces) == len(interfaces):
                return True


def generate_cloud_init_data(data):
    """
    Generate cloud init data from a dictionary.

    Args:
        data (dict): cloud init data to set under desired section.

    Returns:
        str: A generated str for cloud init.

    Example:
        data = {
            "networkData": {
                "version": 2,
                "ethernets": {
                    "eth0": {
                        "dhcp4": True,
                        "addresses": "[ fd10:0:2::2/120 ]",
                        "gateway6": "fd10:0:2::1",
                    }
                }
            }
        }

        with cluster_resource(VirtualMachineForTests)(
            namespace="namespace",
            name="vm",
            body=fedora_vm_body("vm"),
            cloud_init_data=data,
        ) as vm:
            pass
    """
    dict_data = {}
    for section, _data in data.items():
        str_data = ""
        generated_data = yaml.dump(_data, width=1000)
        if section == "userData":
            str_data += "#cloud-config\n"

        for line in generated_data.splitlines():
            str_data += f"{line}\n"
        dict_data[section] = str_data
    return dict_data


def merge_dicts(source_dict, target_dict):
    """Merge nested source_dict into target_dict"""

    for key, value in source_dict.items():
        if isinstance(value, dict):
            node = target_dict.setdefault(key, {})
            merge_dicts(source_dict=value, target_dict=node)
        else:
            target_dict[key] = value

    return target_dict


class VirtualMachineForTests(VirtualMachine):
    def __init__(
        self,
        name,
        namespace,
        body=None,
        eviction=False,
        client=None,
        interfaces=None,
        networks=None,
        node_selector=None,
        service_accounts=None,
        cpu_flags=None,
        cpu_limits=None,
        cpu_requests=None,
        cpu_sockets=None,
        cpu_cores=None,
        cpu_threads=None,
        cpu_model=None,
        memory_requests=None,
        memory_limits=None,
        memory_guest=None,
        cloud_init_data=None,
        machine_type=None,
        image=None,
        ssh=True,
        ssh_secret=None,
        network_model=None,
        network_multiqueue=None,
        pvc=None,
        data_volume=None,
        data_volume_template=None,
        teardown=True,
        cloud_init_type=None,
        attached_secret=None,
        cpu_placement=False,
        isolate_emulator_thread=False,
        iothreads_policy=None,
        dedicated_iothread=False,
        smm_enabled=None,
        pvspinlock_enabled=None,
        efi_params=None,
        diskless_vm=False,
        running=False,
        run_strategy=None,
        disk_io_options=None,
        username=None,
        password=None,
        macs=None,
        interfaces_types=None,
        os_flavor=OS_FLAVOR_FEDORA,
        host_device_name=None,
        gpu_name=None,
        systemctl_support=True,
        vhostmd=False,
        vm_debug_logs=False,
        priority_class_name=None,
        dry_run=None,
        disable_sha2_algorithms=False,
        additional_labels=None,
        generate_unique_name=True,
        node_selector_labels=None,
        vm_instance_type=None,
        vm_preference=None,
    ):
        """
        Virtual machine creation

        Args:
            name (str): VM name
            namespace (str): Namespace name
            body (dict, optional): VM [metadata] and spec
            eviction (bool, default False): If True, set evictionStrategy to LiveMigrate
            client (:obj:`DynamicClient`, optional): admin client or unprivileged client
            interfaces (list, optional): list of interfaces names
            networks (dict, optional)
            node_selector (str, optional): Node name
            service_accounts (list, optional): list of service account names
            cpu_flags (str, optional)
            cpu_limits (quantity, optional): quantity supports string, ints, and floats
            cpu_requests (quantity, optional): quantity supports string, ints, and floats
            cpu_sockets (int, optional)
            cpu_cores (int, optional)
            cpu_threads (int, optional)
            cpu_model (str, optional)
            memory_requests (str, optional)
            memory_limits (str, optional)
            memory_guest (str, optional)
            cloud_init_data (dict, optional): cloud-init dict
            machine_type (str, optional)
            image (str, optional)
            ssh (bool, default: True): If True and using "with" (contextmanager) statement, create an SSH service
            ssh_secret (:obj:,`Secret`, optional): Needs cloud_init_type as cloudInitConfigDrive
            network_model (str, optional)
            network_multiqueue (None/bool, optional, default: None): If not None, set to True/False
            pvc (:obj:`PersistentVolumeClaim`, optional)
            data_volume (:obj:`DataVolume`, optional)
            data_volume_template (dict, optional)
            teardown (bool, default: True)
            cloud_init_type (str, optional): cloud-init type, for example: cloudInitNoCloud, cloudInitConfigDrive
            attached_secret (dict, optional)
            cpu_placement (bool, default: False): If True, set dedicatedCpuPlacement = True
            isolate_emulator_thread (bool, default: False): If True, set isolateEmulatorThread = True.
                Need to explicitly also set cpu_placement = True, as dedicatedCpuPlacement should also be True.
            iothreads_policy (str, optional, default: None): If not None, set to auto/shared
            dedicated_iothread (bool, optional, default: False): If True, set dedicatedIOThread to True
            smm_enabled (None/bool, optional, default: None): If not None, set to True/False
            pvspinlock_enabled (bool, optional, default: None): If not None, set to True/False
            efi_params (dict, optional)
            diskless_vm (bool, default: False): If True, remove VM disks
            running (bool, default: False): If True, running = True
            run_strategy (str, optional): Set runStrategy (run_strategy and running are mutually exclusive)
            disk_io_options (str, optional): Set root disk IO
            username (str, optional): SSH username
            password (str, optional): SSH password
            macs (dict, optional): Dict of {interface_name: mac address}
            interfaces_types (dict, optional): Dict of interfaces names and type ({"iface1": "sriov"})
            os_flavor (str, default: fedora): OS flavor to get SSH login parameters.
                (flavor should be exist in constants.py)
            host_device_name (str, optional): PCI Host Device Name (For Example: "nvidia.com/GV100GL_Tesla_V100")
            gpu_name (str, optional): GPU Device Name (For Example: "nvidia.com/GV100GL_Tesla_V100")
            systemctl_support(bool, default=True): whether OS supports systemctl (RHEL 6 does not)
            vhostmd (bool, optional, default: False): If True, configure vhostmd.
            vm_debug_logs(bool, default=False): if True, add 'debugLogs' label to VM to
                enable libvirt debug logs in the virt-launcher pod.
                Is set to True if py_config["data_collector"] is True.
            priority_class_name (str, optional): The name of the priority class used for the VM
            dry_run (str, default=None): If "All", the resource will be created using the dry_run flag
            disable_sha2_algorithms (bool, default=False): disable openSSH rsa-sha2-256, rsa-sha2-512 algorithms
                when creating a ssh connection
            additional_labels (dict, optional): Dict of additional labels for VM (e.g. {"vm-label": "best-vm"})
            generate_unique_name: if True then it will set dynamic name for the vm, False will use the name of vm passed
            node_selector_labels (str, optional): Labels for node selector.
            vm_instance_type (VirtualMachineInstancetype, optional): instance type object for the VM
            vm_preference (VirtualMachinePreference, optional): preference object for the VM
        """
        # Sets VM unique name - replaces "." with "-" in the name to handle valid values.

        self.name = (
            utilities.infra.unique_name(name=name) if generate_unique_name else name
        )
        super().__init__(
            name=self.name,
            namespace=namespace,
            client=client,
            teardown=teardown,
            privileged_client=get_client(),
            dry_run=dry_run,
            node_selector=node_selector,
            node_selector_labels=node_selector_labels,
        )
        self.body = body
        self.interfaces = interfaces or []
        self.service_accounts = service_accounts or []
        self.networks = networks or {}
        self.node_selector = node_selector
        self.eviction = eviction
        self.cpu_flags = cpu_flags
        self.cpu_limits = cpu_limits
        self.cpu_requests = cpu_requests
        self.cpu_sockets = cpu_sockets
        self.cpu_cores = cpu_cores
        self.cpu_threads = cpu_threads
        self.cpu_model = cpu_model
        self.memory_requests = memory_requests
        self.memory_limits = memory_limits
        self.memory_guest = memory_guest
        self.cloud_init_data = cloud_init_data
        self.machine_type = machine_type
        self.image = image
        self.ssh = ssh
        self.ssh_secret = ssh_secret
        self.custom_service = None
        self.network_model = network_model
        self.network_multiqueue = network_multiqueue
        self.data_volume_template = data_volume_template
        self.cloud_init_type = cloud_init_type
        self.pvc = pvc
        self.attached_secret = attached_secret
        self.cpu_placement = cpu_placement
        self.isolate_emulator_thread = isolate_emulator_thread
        self.iothreads_policy = iothreads_policy
        self.dedicated_iothread = dedicated_iothread
        self.data_volume = data_volume
        self.smm_enabled = smm_enabled
        self.pvspinlock_enabled = pvspinlock_enabled
        self.efi_params = efi_params
        self.diskless_vm = diskless_vm
        self.is_vm_from_template = False
        self.running = running
        self.run_strategy = run_strategy
        self.disk_io_options = disk_io_options
        self.username = username
        self.password = password
        self.macs = macs
        self.interfaces_types = interfaces_types or {}
        self.os_flavor = os_flavor
        self.host_device_name = host_device_name
        self.gpu_name = gpu_name
        self.systemctl_support = systemctl_support
        self.vhostmd = vhostmd
        self.vm_debug_logs = vm_debug_logs or py_config.get("data_collector")
        self.priority_class_name = priority_class_name
        self.disable_sha2_algorithms = disable_sha2_algorithms
        self.additional_labels = additional_labels
        self.node_selector_labels = node_selector_labels
        self.vm_instance_type = vm_instance_type
        self.vm_preference = vm_preference

    def deploy(self, wait=False):
        super().deploy(wait=wait)
        return self

    def clean_up(self):
        if self.exists and self.ready:
            self.stop(wait=True, vmi_delete_timeout=TIMEOUT_8MIN)
        super().clean_up()
        if self.custom_service:
            self.custom_service.delete(wait=True)

    def to_dict(self):
        super().to_dict()
        self.set_labels()
        self.set_rng_device()
        self.generate_body()
        self.set_run_strategy()
        self.set_instance_type()
        self.set_vm_preference()

        self.is_vm_from_template = self._is_vm_from_template()

        template_spec = self.res["spec"]["template"]["spec"]
        # if eviction is set to None, use it
        if self.eviction is None:
            template_spec[EVICTION_STRATEGY] = "None"
        if self.eviction:
            template_spec[EVICTION_STRATEGY] = LIVE_MIGRATE
        template_spec = self.update_node_selector(template_spec=template_spec)
        template_spec = self.update_vm_network_configuration(
            template_spec=template_spec
        )
        template_spec = self.update_vm_cpu_configuration(template_spec=template_spec)
        template_spec = self.update_vm_memory_configuration(template_spec=template_spec)
        template_spec = self.set_smm(template_spec=template_spec)
        template_spec = self.set_pvspinlock(template_spec=template_spec)
        template_spec = self.set_efi_params(template_spec=template_spec)
        template_spec = self.set_machine_type(template_spec=template_spec)
        template_spec = self.set_iothreads_policy(template_spec=template_spec)
        template_spec = self.set_hostdevice(template_spec=template_spec)
        template_spec = self.set_gpu(template_spec=template_spec)
        template_spec = self.set_disk_io_configuration(template_spec=template_spec)
        template_spec = self.set_priority_class(template_spec=template_spec)
        # Either update storage and cloud-init configuration or remove disks from spec
        if self.diskless_vm:
            template_spec = self.set_diskless_vm(template_spec=template_spec)
        else:
            template_spec = self.update_vm_storage_configuration(
                template_spec=template_spec
            )
            template_spec = self.set_service_accounts(template_spec=template_spec)
            # cloud-init disks must be set after DV disks in order to boot from DV.
            template_spec = self.update_vm_cloud_init_data(template_spec=template_spec)
            template_spec = self.set_vhostmd(template_spec=template_spec)

            template_spec = self.update_vm_secret_configuration(
                template_spec=template_spec
            )

            # VMs do not necessarily have self.cloud_init_data
            # cloud-init will not be set for OS in FLAVORS_EXCLUDED_FROM_CLOUD_INIT
            if self.ssh and self.os_flavor not in FLAVORS_EXCLUDED_FROM_CLOUD_INIT:
                if self.ssh_secret is None:
                    template_spec = self.enable_ssh_in_cloud_init_data(
                        template_spec=template_spec
                    )
                # NOTE: When using ssh_secret we need cloud_init_type as cloudInitConfigDrive
                # networkData does not work with cloudInitConfigDrive
                # https://bugzilla.redhat.com/show_bug.cgi?id=1941470 <skip-bug-check>
                if self.cloud_init_type == CLOUND_INIT_CONFIG_DRIVE and self.ssh_secret:
                    template_spec = self.update_vm_ssh_secret_configuration(
                        template_spec=template_spec
                    )

    def update_node_selector(self, template_spec):
        if self.node_selector_spec:
            template_spec["nodeSelector"] = self.node_selector_spec
        return template_spec

    def set_disk_io_configuration(self, template_spec):
        if self.disk_io_options or self.dedicated_iothread:
            disks_spec = (
                template_spec.setdefault("domain", {})
                .setdefault("devices", {})
                .setdefault("disks", [])
            )
            for disk in disks_spec:
                if disk["name"] == ROOTDISK:
                    if self.disk_io_options:
                        disk["io"] = self.disk_io_options
                    if self.dedicated_iothread:
                        disk["dedicatedIOThread"] = self.dedicated_iothread
                    break

            template_spec["domain"]["devices"]["disks"] = disks_spec

        return template_spec

    def set_gpu(self, template_spec):
        if self.gpu_name:
            template_spec.setdefault("domain", {}).setdefault("devices", {}).setdefault(
                "gpus", []
            ).append(
                {
                    "deviceName": self.gpu_name,
                    "name": "gpu",
                }
            )

        return template_spec

    def set_hostdevice(self, template_spec):
        if self.host_device_name:
            template_spec.setdefault("domain", {}).setdefault("devices", {}).setdefault(
                "hostDevices", []
            ).append(
                {
                    "deviceName": self.host_device_name,
                    "name": "hostdevice",
                }
            )

        return template_spec

    def set_diskless_vm(self, template_spec):
        template_spec.get("domain", {}).get("devices", {}).pop("disks", None)
        # As of https://bugzilla.redhat.com/show_bug.cgi?id=1954667 <skip-bug-check>, it is not possible to create a VM
        # with volume(s) without corresponding disks
        template_spec.pop("volumes", None)

        return template_spec

    def set_machine_type(self, template_spec):
        if self.machine_type:
            template_spec.setdefault("domain", {}).setdefault("machine", {})[
                "type"
            ] = self.machine_type

        return template_spec

    def set_iothreads_policy(self, template_spec):
        if self.iothreads_policy:
            template_spec.setdefault("domain", {})[
                "ioThreadsPolicy"
            ] = self.iothreads_policy

        return template_spec

    def set_efi_params(self, template_spec):
        if self.efi_params is not None:
            template_spec.setdefault("domain", {}).setdefault(
                "firmware", {}
            ).setdefault("bootloader", {})["efi"] = self.efi_params

        return template_spec

    def set_smm(self, template_spec):
        if self.smm_enabled is not None:
            template_spec.setdefault("domain", {}).setdefault(
                "features", {}
            ).setdefault("smm", {})["enabled"] = self.smm_enabled

        return template_spec

    def set_pvspinlock(self, template_spec):
        if self.pvspinlock_enabled is not None:
            template_spec.setdefault("domain", {}).setdefault(
                "features", {}
            ).setdefault("pvspinlock", {})["enabled"] = self.pvspinlock_enabled

        return template_spec

    def set_priority_class(self, template_spec):
        if self.priority_class_name:
            template_spec["priorityClassName"] = self.priority_class_name

        return template_spec

    def set_rng_device(self):
        # Create rng device so the vm will be able to use /dev/rnd without
        # waiting for entropy collecting.
        self.res.setdefault("spec", {}).setdefault("template", {}).setdefault(
            "spec", {}
        ).setdefault("domain", {}).setdefault("devices", {}).setdefault("rng", {})

    def set_service_accounts(self, template_spec):
        for sa in self.service_accounts:
            template_spec.setdefault("domain", {}).setdefault("devices", {}).setdefault(
                "disks", []
            ).append({"disk": {}, "name": sa})
            template_spec.setdefault("volumes", []).append(
                {"name": sa, "serviceAccount": {"serviceAccountName": sa}}
            )

        return template_spec

    def set_vhostmd(self, template_spec):
        name = "vhostmd"
        if self.vhostmd:
            template_spec.setdefault("domain", {}).setdefault("devices", {}).setdefault(
                "disks", []
            ).append({"disk": {"bus": "virtio"}, "name": name})
            template_spec.setdefault("volumes", []).append(
                {"name": name, "downwardMetrics": {}}
            )

        return template_spec

    def set_labels(self):
        vm_labels = (
            self.res["spec"]["template"]
            .setdefault("metadata", {})
            .setdefault("labels", {})
        )
        vm_labels.update(
            {
                f"{Resource.ApiGroup.KUBEVIRT_IO}/vm": self.name,
                f"{Resource.ApiGroup.KUBEVIRT_IO}/domain": self.name,
            }
        )

        if self.additional_labels:
            vm_labels.update(self.additional_labels)

        if self.vm_debug_logs:
            vm_labels["debugLogs"] = "true"

    def set_run_strategy(self):
        # runStrategy and running are mutually exclusive
        #
        # From RunStrategy() in
        # https://github.com/kubevirt/kubevirt/blob/master/staging/src/kubevirt.io/client-go/api/v1/types.go
        # if vm.spec.running is set, that will be mapped to runStrategy:
        #   false: RunStrategyHalted
        #   true: RunStrategyAlways
        #
        # To create a VM resource, but not begin VM cloning, use VirtualMachine.RunStrategy.MANUAL
        if self.run_strategy:
            self.res["spec"].pop("running", None)
            self.res["spec"]["runStrategy"] = self.run_strategy
        else:
            self.res["spec"]["running"] = self.running

    def set_instance_type(self):
        if self.vm_instance_type:
            self.res["spec"]["instancetype"] = {
                "kind": self.vm_instance_type.kind,
                "name": self.vm_instance_type.name,
            }

    def set_vm_preference(self):
        if self.vm_preference:
            self.res["spec"]["preference"] = {
                "kind": self.vm_preference.kind,
                "name": self.vm_preference.name,
            }

    def _is_vm_from_template(self):
        return (
            f"{self.ApiGroup.VM_KUBEVIRT_IO}/template"
            in self.res["metadata"].setdefault("labels", {}).keys()
        )

    def generate_body(self):
        if self.body:
            if self.body.get("metadata"):
                # We must set name in Template, since we use a unique name here we override it.
                self.res["metadata"] = self.body["metadata"]
                self.res["metadata"]["name"] = self.name

            self.res["spec"] = self.body["spec"]

    def update_vm_memory_configuration(self, template_spec):
        # Faster VMI start time
        if self.os_flavor == OS_FLAVOR_WINDOWS and not self.memory_requests:
            self.memory_requests = Images.Windows.DEFAULT_MEMORY_SIZE

        if self.memory_requests:
            template_spec.setdefault("domain", {}).setdefault(
                "resources", {}
            ).setdefault("requests", {})["memory"] = self.memory_requests

        if self.memory_limits:
            template_spec.setdefault("domain", {}).setdefault(
                "resources", {}
            ).setdefault("limits", {})["memory"] = self.memory_limits

        if self.memory_guest:
            template_spec.setdefault("domain", {}).setdefault("memory", {})[
                "guest"
            ] = self.memory_guest

        return template_spec

    def update_vm_network_configuration(self, template_spec):
        for iface_name in self.interfaces:
            iface_type = self.interfaces_types.get(iface_name, "bridge")
            network_dict = {"name": iface_name, iface_type: {}}

            if self.macs:
                network_dict["macAddress"] = self.macs.get(iface_name)

            template_spec.setdefault("domain", {}).setdefault("devices", {}).setdefault(
                "interfaces", []
            ).append(network_dict)

        for iface_name, network in self.networks.items():
            template_spec.setdefault("networks", []).append(
                {"name": iface_name, "multus": {"networkName": network}}
            )

        if self.network_model:
            template_spec.setdefault("domain", {}).setdefault("devices", {}).setdefault(
                "interfaces", [{}]
            )[0]["model"] = self.network_model

        if self.network_multiqueue is not None:
            template_spec.setdefault("domain", {}).setdefault("devices", {}).update(
                {"networkInterfaceMultiqueue": self.network_multiqueue}
            )

        return template_spec

    def update_vm_cloud_init_data(self, template_spec):
        if self.cloud_init_data:
            cloud_init_volume = vm_cloud_init_volume(vm_spec=template_spec)
            cloud_init_volume_type = self.cloud_init_type or CLOUD_INIT_NO_CLOUD
            generated_cloud_init = generate_cloud_init_data(data=self.cloud_init_data)
            existing_cloud_init_data = cloud_init_volume.get(cloud_init_volume_type)
            # If spec already contains cloud init data
            if existing_cloud_init_data:
                cloud_init_volume[cloud_init_volume_type][
                    "userData"
                ] += generated_cloud_init["userData"].strip("#cloud-config")
            else:
                cloud_init_volume[cloud_init_volume_type] = generated_cloud_init

            template_spec = vm_cloud_init_disk(vm_spec=template_spec)

        return template_spec

    def enable_ssh_in_cloud_init_data(self, template_spec):
        cloud_init_volume = vm_cloud_init_volume(vm_spec=template_spec)
        cloud_init_volume_type = self.cloud_init_type or CLOUD_INIT_NO_CLOUD

        template_spec = vm_cloud_init_disk(vm_spec=template_spec)

        cloud_init_volume.setdefault(cloud_init_volume_type, {}).setdefault(
            "userData", ""
        )

        # Saving in an intermediate string for readability
        cloud_init_user_data = cloud_init_volume[cloud_init_volume_type]["userData"]

        # Populate userData with OS-related login credentials; not needed for a VM from template
        if not self.is_vm_from_template:
            login_params = OS_LOGIN_PARAMS[self.os_flavor]
            login_generated_data = generate_cloud_init_data(
                data={
                    "userData": {
                        "user": login_params["username"],
                        "password": login_params["password"],
                        "chpasswd": {"expire": False},
                    }
                }
            )
            # Newline needed in case userData is not empty
            cloud_init_user_data_newline = "\n" if cloud_init_user_data else ""
            cloud_init_user_data += (
                f"{cloud_init_user_data_newline}{login_generated_data['userData']}"
            )

        # Add RSA to authorized_keys to enable login using an SSH key
        authorized_key = utilities.infra.authorized_key(
            private_key_path=os.environ[CNV_VM_SSH_KEY_PATH]
        )
        cloud_init_user_data += f"\nssh_authorized_keys:\n [{authorized_key}]"

        # Enable LEGACY crypto policies - needed until keys updated to ECDSA
        # Enable PasswordAuthentication in /etc/ssh/sshd_config
        # Enable SSH service and restart SSH service
        run_cmd_commands = [
            (
                # TODO: Remove LEGACY ssh-rsa support after ECDSA supported by test
                "grep ssh-rsa /etc/crypto-policies/back-ends/opensshserver.config || "
                "sudo update-crypto-policies --set LEGACY || true"
            ),
            (
                r"sudo sed -i 's/^#\?PasswordAuthentication no/PasswordAuthentication yes/g' "
                "/etc/ssh/sshd_config"
            ),
            "sudo systemctl enable sshd" if self.systemctl_support else "",
            (
                "sudo systemctl restart sshd"
                if self.systemctl_support
                else "sudo /etc/init.d/sshd restart"
            ),
        ]

        run_ssh_generated_data = generate_cloud_init_data(
            data={"runcmd": run_cmd_commands}
        )

        # If runcmd already exists in userData, add run_cmd_commands before any other command
        runcmd_prefix = "runcmd:"
        if runcmd_prefix in cloud_init_user_data:
            cloud_init_user_data = re.sub(
                runcmd_prefix,
                f"{runcmd_prefix}\n{run_ssh_generated_data['runcmd']}",
                cloud_init_user_data,
            )
        else:
            cloud_init_user_data += f"\nruncmd: {run_cmd_commands}"

        cloud_init_volume[cloud_init_volume_type]["userData"] = cloud_init_user_data

        return template_spec

    def update_vm_cpu_configuration(self, template_spec):
        # cpu settings
        if self.cpu_flags:
            template_spec.setdefault("domain", {})["cpu"] = self.cpu_flags

        if self.cpu_limits:
            template_spec.setdefault("domain", {}).setdefault(
                "resources", {}
            ).setdefault("limits", {})
            template_spec["domain"]["resources"]["limits"].update(
                {"cpu": self.cpu_limits}
            )

        if self.cpu_requests:
            template_spec.setdefault("domain", {}).setdefault(
                "resources", {}
            ).setdefault("requests", {})
            template_spec["domain"]["resources"]["requests"].update(
                {"cpu": self.cpu_requests}
            )

        if self.cpu_cores:
            template_spec.setdefault("domain", {}).setdefault("cpu", {})[
                "cores"
            ] = self.cpu_cores

        # Faster VMI start time
        if self.os_flavor == OS_FLAVOR_WINDOWS and not self.cpu_threads:
            self.cpu_threads = Images.Windows.DEFAULT_CPU_THREADS

        if self.cpu_threads:
            template_spec.setdefault("domain", {}).setdefault("cpu", {})[
                "threads"
            ] = self.cpu_threads

        if self.cpu_sockets:
            template_spec.setdefault("domain", {}).setdefault("cpu", {})[
                "sockets"
            ] = self.cpu_sockets

        if self.cpu_placement:
            template_spec.setdefault("domain", {}).setdefault("cpu", {})[
                "dedicatedCpuPlacement"
            ] = True

        if self.isolate_emulator_thread:
            # This setting has to be specified in a combination with
            # cpu_placement = True. Only valid if dedicatedCpuPlacement is True.
            template_spec.setdefault("domain", {}).setdefault("cpu", {})[
                "isolateEmulatorThread"
            ] = True

        if self.cpu_model:
            template_spec.setdefault("domain", {}).setdefault("cpu", {})[
                "model"
            ] = self.cpu_model

        return template_spec

    def update_vm_storage_configuration(self, template_spec):
        # image must be set before DV in order to boot from it.
        if self.image:
            template_spec.setdefault("domain", {}).setdefault("devices", {}).setdefault(
                "disks", []
            ).append({"disk": {"bus": "virtio"}, "name": "containerdisk"})
            template_spec.setdefault("volumes", []).append(
                {"name": "containerdisk", "containerDisk": {"image": self.image}}
            )

        # DV/PVC info may be taken from self.data_volume_template, self.data_volume or self.pvc
        # Needed only for VMs which are not created from common templates
        if (
            self.data_volume_template or self.data_volume or self.pvc
        ) and not self.is_vm_from_template:
            access_mode = self.get_storage_configuration()

            # For storage class that is not ReadWriteMany - evictionStrategy should be set as "None" in the VM
            # (Except when evictionStrategy is explicitly set)
            if not self.eviction and DataVolume.AccessMode.RWX not in access_mode:
                LOGGER.info(
                    f"{EVICTION_STRATEGY} explicitly set to 'None' in VM because data volume access mode is not RWX"
                )
                template_spec[EVICTION_STRATEGY] = "None"

            if self.pvc:
                pvc_disk_name = f"{self.pvc.name}-pvc-disk"
                template_spec.setdefault("domain", {}).setdefault(
                    "devices", {}
                ).setdefault("disks", []).append(
                    {"disk": {"bus": "virtio"}, "name": pvc_disk_name}
                )
                template_spec.setdefault("volumes", []).append(
                    {
                        "name": pvc_disk_name,
                        "persistentVolumeClaim": {"claimName": self.pvc.name},
                    }
                )
            # self.data_volume / self.data_volume_template
            else:
                data_volume_name = (
                    self.data_volume.name
                    if self.data_volume
                    else self.data_volume_template["metadata"]["name"]
                )
                template_spec.setdefault("domain", {}).setdefault(
                    "devices", {}
                ).setdefault("disks", []).append(
                    {"disk": {"bus": "virtio"}, "name": "dv-disk"}
                )
                template_spec.setdefault("volumes", []).append(
                    {
                        "name": "dv-disk",
                        "dataVolume": {"name": data_volume_name},
                    }
                )

            if self.data_volume_template:
                self.res["spec"].setdefault("dataVolumeTemplates", []).append(
                    self.data_volume_template
                )

        return template_spec

    def update_vm_secret_configuration(self, template_spec):
        if self.attached_secret:
            volume_name = self.attached_secret["volume_name"]
            template_spec.setdefault("domain", {}).setdefault("devices", {}).setdefault(
                "disks", []
            ).append(
                {
                    "disk": {},
                    "name": volume_name,
                    "serial": self.attached_secret["serial"],
                }
            )
            template_spec.setdefault("volumes", []).append(
                {
                    "name": volume_name,
                    "secret": {"secretName": self.attached_secret["secret_name"]},
                }
            )

        return template_spec

    def update_vm_ssh_secret_configuration(self, template_spec):
        template_spec.setdefault("accessCredentials", []).append(
            {
                "sshPublicKey": {
                    "source": {"secret": {"secretName": self.ssh_secret.name}},
                    "propagationMethod": {"configDrive": {}},
                }
            }
        )
        return template_spec

    def custom_service_enable(
        self,
        service_name,
        port,
        service_type=None,
        service_ip=None,
        ip_family_policy=None,
        ip_families=None,
    ):
        """
        service_type is set with K8S default service type (ClusterIP)
        service_ip - relevant for node port; default will be set to vm node IP
        ip_families - list of IP families to be supported in the service (IPv4/6 or both)
        ip_family_policy - SingleStack, RequireDualStack or PreferDualStack
        To use the service: custom_service.service_ip() and custom_service.service_port
        """
        self.custom_service = ServiceForVirtualMachineForTests(
            name=f"{service_name}-{self.name}"[:63],
            namespace=self.namespace,
            vm=self,
            port=port,
            service_type=service_type,
            target_ip=service_ip,
            ip_family_policy=ip_family_policy,
            ip_families=ip_families,
        )
        self.custom_service.create(wait=True)

    def get_storage_configuration(self):
        def _sc_name_for_storage_api():
            return self.data_volume_template["spec"]["storage"].get(
                "storageClassName",
                utilities.storage.default_storage_class(client=self.client).name,
            )

        api_name = (
            "pvc"
            if self.data_volume_template
            and self.data_volume_template["spec"].get("pvc")
            else "storage"
        )
        return (
            self.data_volume.pvc.instance.spec.accessModes
            if self.data_volume
            else self.pvc.instance.spec.accessModes
            if self.pvc
            else self.data_volume_template["spec"][api_name].get("accessModes")
            or StorageProfile(name=_sc_name_for_storage_api()).instance.status[
                "claimPropertySets"
            ][0]["accessModes"]
        )

    @property
    def virtctl_port_forward_cmd(self):
        return f"virtctl port-forward --stdio=true {self.name}.{self.namespace} {SSH_PORT_22}"

    @property
    def ssh_exec(self):
        # In order to use this property VM should be created with ssh=True
        login_params = OS_LOGIN_PARAMS[self.os_flavor]
        self.username = self.username or login_params["username"]
        self.password = self.password or login_params["password"]

        LOGGER.info(
            f"Username: {self.username}, password: {self.password}, SSH key: {os.environ[CNV_VM_SSH_KEY_PATH]}\n"
            f"SSH command: ssh -o 'ProxyCommand={self.virtctl_port_forward_cmd}' {self.username}@{self.name}"
        )
        host = Host(hostname=self.name)
        # For SSH using a key, the public key needs to reside on the server.
        # As the tests use a given set of credentials, this cannot be done in Windows/Cirros.
        if self.os_flavor in FLAVORS_EXCLUDED_FROM_CLOUD_INIT:
            host_user = user.User(name=self.username, password=self.password)
        else:
            host_user = user.UserWithPKey(
                name=self.username, private_key=os.environ[CNV_VM_SSH_KEY_PATH]
            )
        host.executor_user = host_user
        host.executor_factory = ssh.RemoteExecutorFactory(
            sock=self.virtctl_port_forward_cmd,
            disabled_algorithms={"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]}
            if self.disable_sha2_algorithms
            else None,
        )
        return host

    def wait_for_specific_status(
        self, status, timeout=TIMEOUT_3MIN, sleep=TIMEOUT_5SEC
    ):
        LOGGER.info(f"Wait for {self.kind} {self.name} status to be {status}")
        samples = TimeoutSampler(
            wait_timeout=timeout, sleep=sleep, func=lambda: self.printable_status
        )
        try:
            for sample in samples:
                if sample == status:
                    return
        except TimeoutExpiredError:
            LOGGER.error(f"Status of {self.kind} {self.name} is {status}")
            raise


class VirtualMachineForTestsFromTemplate(VirtualMachineForTests):
    def __init__(
        self,
        name,
        namespace,
        client,
        labels=None,
        data_source=None,
        data_volume_template=None,
        existing_data_volume=None,
        networks=None,
        interfaces=None,
        ssh=True,
        vm_dict=None,
        cpu_cores=None,
        cpu_threads=None,
        cpu_sockets=None,
        cpu_model=None,
        cpu_flags=None,
        cpu_placement=False,
        isolate_emulator_thread=False,
        memory_requests=None,
        network_model=None,
        network_multiqueue=None,
        cloud_init_data=None,
        node_selector=None,
        attached_secret=None,
        termination_grace_period=180,
        diskless_vm=False,
        run_strategy=None,
        disk_options_vm=None,
        smm_enabled=None,
        pvspinlock_enabled=None,
        efi_params=None,
        macs=None,
        interfaces_types=None,
        host_device_name=None,
        gpu_name=None,
        iothreads_policy=None,
        dedicated_iothread=False,
        cloned_dv_size=None,
        systemctl_support=True,
        vhostmd=False,
        machine_type=None,
        teardown=True,
        use_full_storage_api=False,
        dry_run=None,
        template_params=None,
        template_object=None,
        non_existing_pvc=False,
        disable_sha2_algorithms=False,
        data_volume_template_from_vm_spec=False,
        eviction=False,
        sno_cluster=False,
    ):
        """
        VM creation using common templates.

        Args:
            data_source (obj `DataSource`): DS object points to a golden image PVC.
                VM's disk will be cloned from the PVC.
            data_volume_template (dict): dataVolumeTemplates dict to replace template's default dataVolumeTemplates
            existing_data_volume (obj `DataVolume`): An existing DV object that will be used as the VM's volume. Cloning
                will not be done and the template's dataVolumeTemplates will be removed.
            use_full_storage_api (bool, default=False): Target PVC storage params are not explicitly set if True.
                IF False, storage api will be used but target PVC storage name will be taken from self.dv. This is done
                to avoid modifying cluster default SC.
            dry_run (str, default=None): If "All", the VM will be created using the dry_run flag
            template_params (dict, optional): dict with template parameters as keys and values
            template_object (Template, optional): Template object to create the VM from
            non_existing_pvc(bool, default=False): If True, referenced PVC in DataSource is missing
            disable_sha2_algorithms (bool, default=False): disable openSSH rsa-sha2-256, rsa-sha2-512 algorithms
                when creating a ssh connection
            data_volume_template_from_vm_spec (bool, default=False): Use (and don't manipulate) VM's DataVolumeTemplates
            eviction (bool, default False): If True, set evictionStrategy to LiveMigrate explicitly
        Returns:
            obj `VirtualMachine`: VM resource
        """
        super().__init__(
            name=name,
            namespace=namespace,
            client=client,
            networks=networks,
            interfaces=interfaces,
            ssh=ssh,
            network_model=network_model,
            network_multiqueue=network_multiqueue,
            cpu_cores=cpu_cores,
            cpu_threads=cpu_threads,
            cpu_model=cpu_model,
            cpu_sockets=cpu_sockets,
            cpu_flags=cpu_flags,
            cpu_placement=cpu_placement,
            isolate_emulator_thread=isolate_emulator_thread,
            memory_requests=memory_requests,
            cloud_init_data=cloud_init_data,
            node_selector=node_selector,
            attached_secret=attached_secret,
            data_volume_template=data_volume_template,
            diskless_vm=diskless_vm,
            run_strategy=run_strategy,
            disk_io_options=disk_options_vm,
            smm_enabled=smm_enabled,
            pvspinlock_enabled=pvspinlock_enabled,
            efi_params=efi_params,
            macs=macs,
            interfaces_types=interfaces_types,
            host_device_name=host_device_name,
            gpu_name=gpu_name,
            iothreads_policy=iothreads_policy,
            dedicated_iothread=dedicated_iothread,
            systemctl_support=systemctl_support,
            vhostmd=vhostmd,
            machine_type=machine_type,
            teardown=teardown,
            dry_run=dry_run,
            disable_sha2_algorithms=disable_sha2_algorithms,
        )
        self.template_labels = labels
        self.data_source = data_source
        self.data_volume_template = data_volume_template
        self.existing_data_volume = existing_data_volume
        self.vm_dict = vm_dict
        self.cpu_threads = cpu_threads
        self.node_selector = node_selector
        self.termination_grace_period = termination_grace_period
        self.cloud_init_data = cloud_init_data
        self.cloned_dv_size = cloned_dv_size
        self.use_full_storage_api = use_full_storage_api
        self.access_modes = None  # required for evictionStrategy policy
        self.template_params = template_params
        self.template_object = template_object
        self.non_existing_pvc = non_existing_pvc
        self.data_volume_template_from_vm_spec = data_volume_template_from_vm_spec
        self.eviction = eviction
        self.sno_cluster = sno_cluster

    def to_dict(self):
        self.os_flavor = self._extract_os_from_template()
        self.body = self.process_template()
        super().to_dict()

        if self.vm_dict:
            merge_dicts(source_dict=self.vm_dict, target_dict=self.res)

        spec = self.res["spec"]["template"]["spec"]

        # terminationGracePeriodSeconds for Windows is set to 1hr; this may affect VMI deletion
        # If termination_grace_period is not provided, terminationGracePeriodSeconds will be set to 180
        spec["terminationGracePeriodSeconds"] = self.termination_grace_period

        # Nothing to do if source PVC (referenced in DataSource) does not exist
        if self.non_existing_pvc:
            LOGGER.info("Referenced PVC does not exist")
        # Nothing to do if consuming dataVolumeTemplates already set in the VM spec
        elif self.data_volume_template_from_vm_spec:
            LOGGER.info(
                "VM spec includes DataVolume, which will be used for storing the VM image."
            )
            self.access_modes = self.res["spec"]["dataVolumeTemplates"][0]["spec"][
                "storage"
            ].get("accessModes", [])
        # For diskless_vm, volumes are removed so dataVolumeTemplates (referencing volumes) should be removed as well
        elif self.diskless_vm:
            del self.res["spec"]["dataVolumeTemplates"]
        # Existing DV will be used as the VM's DV; dataVolumeTemplates is not needed
        elif self.existing_data_volume:
            del self.res["spec"]["dataVolumeTemplates"]
            spec = self._update_vm_storage_config(
                spec=spec, name=self.existing_data_volume.name
            )
            self.access_modes = self.existing_data_volume.pvc.instance.spec.accessModes
        # Template's dataVolumeTemplates will be replaced with self.data_volume_template
        elif self.data_volume_template:
            self.res["spec"]["dataVolumeTemplates"] = [self.data_volume_template]
            spec = self._update_vm_storage_config(
                spec=spec, name=self.data_volume_template["metadata"]["name"]
            )
            self.access_modes = self.data_volume_template["spec"].get("pvc", {}).get(
                "accessModes", []
            ) or self.data_volume_template["spec"].get("storage", {}).get(
                "accessModes", []
            )
        # Otherwise clone PVC referenced in self.data_source
        else:
            pvc_from_data_source = self.data_source.instance.spec.source.pvc
            golden_image_dv = DataVolume(
                name=pvc_from_data_source.name,
                namespace=pvc_from_data_source.namespace,
            )
            source_dv_pvc_spec = golden_image_dv.pvc.instance.spec
            dv_storage_pvc_spec = self.res["spec"]["dataVolumeTemplates"][0]["spec"][
                "storage"
            ]
            self.access_modes = source_dv_pvc_spec.accessModes
            # dataVolumeTemplates needs to be updated with the needed storage size,
            # if the size of the golden_image is more than the Template's default storage size.
            # else use the source DV storage size.
            dv_storage_pvc_spec.setdefault("resources", {}).setdefault("requests", {})[
                "storage"
            ] = (self.cloned_dv_size or source_dv_pvc_spec.resources.requests.storage)
            if not self.use_full_storage_api:
                dv_storage_pvc_spec[
                    "storageClassName"
                ] = source_dv_pvc_spec.storageClassName

        # For storage class that is not ReadWriteMany- evictionStrategy should be set as "None" in the VM
        # (Except when evictionStrategy is explicitly set)
        # To apply this logic, self.access_modes should be available.
        if not self.sno_cluster and (
            not self.eviction
            and not (self.diskless_vm or self.non_existing_pvc)
            and DataVolume.AccessMode.RWX not in self.access_modes
        ):
            spec[EVICTION_STRATEGY] = "None"

        # On PSI cluster Windows VM with hyperv/reenlightenment flag can't be migrated,
        # current workaround removes the flag when VM created from the template
        if (
            os.environ.get(WORKERS_TYPE) == utilities.infra.ClusterHosts.Type.VIRTUAL
            and OS_FLAVOR_WINDOWS in self.os_flavor
        ):
            LOGGER.warning(
                "Removing hyperv/reenlightenment flag for Windows VM on PSI cluster"
            )
            del spec["domain"]["features"]["hyperv"]["reenlightenment"]

    def _update_vm_storage_config(self, spec, name):
        # volume name should be updated
        for volume in spec["volumes"]:
            if "dataVolume" in volume:
                volume["dataVolume"]["name"] = name

        return spec

    def _extract_os_from_template(self):
        os_name = (
            [label for label in self.template_labels if Template.Labels.OS in label][0]
            if self.template_labels is not None
            else self.template_object.instance.objects[
                0
            ].spec.template.metadata.annotations[f"{self.ApiGroup.VM_KUBEVIRT_IO}/os"]
        )
        # Extract only from strings such as: "fedora37", "os.template.kubevirt.io/fedora37" will return "fedora"
        return re.search(r"(.*/)?(?P<os>[a-z]+)", os_name)["os"]

    def process_template(self):
        # Common templates use golden image clone as a default for VM DV
        # DATA_SOURCE_NAME - to support minor releases, this value needs to be passed. Currently
        # the templates only have one name per major OS.
        # DATA_SOURCE_NAMESPACE parameters is not passed so the default value will be used.
        # If existing DV or custom dataVolumeTemplates are used, use mock source PVC name and namespace
        template_kwargs = {
            "NAME": self.name,
            DATA_SOURCE_NAME: self.data_source.name
            if self.data_source
            else "mock-data-source",
            DATA_SOURCE_NAMESPACE: self.data_source.namespace
            if self.data_source
            else "mock-data-source-ns",
        }

        # Set password for non-Windows VMs; for Windows VM, the password is already set in the image
        if OS_FLAVOR_WINDOWS not in self.os_flavor:
            template_kwargs["CLOUD_USER_PASSWORD"] = OS_LOGIN_PARAMS[self.os_flavor][
                "password"
            ]

        if self.template_params:
            template_kwargs.update(self.template_params)

        template_object = self.template_object or get_template_by_labels(
            admin_client=self.client, template_labels=self.template_labels
        )
        resources_list = template_object.process(client=get_client(), **template_kwargs)
        for resource in resources_list:
            if (
                resource["kind"] == VirtualMachine.kind
                and resource["metadata"]["name"] == self.name
            ):
                return resource

        raise ValueError(f"Template not found for {self.name}")


def vm_console_run_commands(
    console_impl, vm, commands, timeout=TIMEOUT_1MIN, verify_commands_output=True
):
    """
    Run a list of commands inside VM and (if verify_commands_output) check all commands return 0.
    If return code other than 0 then it will break execution and raise exception.

    Args:
        console_impl (Console): Console implementation (RHEL, Fedora, etc)
        vm (obj): VirtualMachine
        commands (list): List of commands
        timeout (int): Time to wait for the command output
        verify_commands_output (book): Check commands return 0
    """
    with console_impl(vm=vm) as vmc:
        for command in commands:
            LOGGER.info(f"Execute {command} on {vm.name}")
            vmc.sendline(command)
            if verify_commands_output:
                vmc.sendline(
                    "echo rc==$?=="
                )  # This construction rc==$?== is unique. Return code validation
                try:
                    vmc.expect("rc==0==", timeout=timeout)  # Expected return code is 0
                except pexpect.exceptions.TIMEOUT:
                    raise CommandExecFailed(command)
            else:
                vmc.expect(".*")


def fedora_vm_body(name):
    pull_secret = None
    if py_config["distribution"] == "downstream":
        pull_secret = utilities.infra.generate_openshift_pull_secret_file()

    # Make sure we can find the file even if utilities was installed via pip.
    yaml_file = os.path.abspath("utilities/manifests/vm-fedora.yaml")

    with open(yaml_file, "r") as fd:
        data = fd.read()

    image = re.findall(r"image: (.*)", data)[0]

    image_info = get_oc_image_info(image=image, pull_secret=pull_secret)
    image_digest = image_info["digest"]
    generated_data = re.sub(image, f"{image}@{image_digest}", data)
    return generate_dict_from_yaml_template(
        stream=io.StringIO(generated_data), name=name
    )


def kubernetes_taint_exists(node):
    taints = node.instance.spec.taints
    if taints:
        return any(
            taint.key == K8S_TAINT and taint.effect == NO_SCHEDULE for taint in taints
        )


class ServiceForVirtualMachineForTests(Service):
    def __init__(
        self,
        name,
        namespace,
        vm,
        port,
        service_type=Service.Type.CLUSTER_IP,
        target_ip=None,
        ip_family_policy=IP_FAMILY_POLICY_PREFER_DUAL_STACK,
        ip_families=None,
        teardown=True,
        dry_run=None,
    ):
        super().__init__(
            name=name,
            namespace=namespace,
            teardown=teardown,
            dry_run=dry_run,
        )
        self.vm = vm
        self.vmi = vm.vmi
        self.port = port
        self.service_type = service_type
        self.target_ip = target_ip
        self.ip_family_policy = ip_family_policy
        self.ip_families = ip_families

    def to_dict(self):
        super().to_dict()
        self.res["spec"] = {
            "ports": [{"port": self.port, "protocol": "TCP"}],
            "selector": {"kubevirt.io/domain": self.vm.name},
            "sessionAffinity": "None",
            "type": self.service_type,
        }

        self.res["spec"]["ipFamilyPolicy"] = self.ip_family_policy
        if self.ip_families:
            self.res["spec"]["ipFamilies"] = self.ip_families

    def service_ip(self, ip_family=None):
        if self.service_type == Service.Type.CLUSTER_IP:
            if ip_family:
                cluster_ips = [
                    cluster_ip
                    for cluster_ip in self.vm.custom_service.instance.spec.clusterIPs
                    if str(ipaddress.ip_address(cluster_ip).version) in ip_family
                ]
                assert (
                    cluster_ips
                ), f"No {ip_family} addresses in service {self.vm.custom_service.name}"
                return cluster_ips[0]

            return self.instance.spec.clusterIP

        vm_node = Node(
            client=get_client(),
            name=self.vmi.instance.status.nodeName,
        )
        if self.service_type == Service.Type.NODE_PORT:
            if ip_family:
                internal_ips = [
                    internal_ip
                    for internal_ip in vm_node.instance.status.addresses
                    if str(ipaddress.ip_address(internal_ip).version) in ip_family
                ]
                assert internal_ips, f"No {ip_family} addresses in node {vm_node.name}"
                return internal_ips[0]

            return self.target_ip or vm_node.internal_ip

    @property
    def service_port(self):
        if self.service_type == Service.Type.CLUSTER_IP:
            return self.instance.attributes.spec.ports[0]["port"]

        if self.service_type == Service.Type.NODE_PORT:
            node_port = utilities.infra.camelcase_to_mixedcase(
                camelcase_str=self.service_type
            )
            return self.instance.attributes.spec.ports[0][node_port]


class Prometheus(object):
    """
    For accessing Prometheus cluster metrics

    Prometheus HTTP API doc:
    https://prometheus.io/docs/prometheus/latest/querying/api/

    Argument for query method should be the entire string following the server address
        e.g.
        prometheus = Prometheus()
        up = prometheus.query("/api/v1/query?query=up")
    """

    def __init__(
        self,
        namespace="openshift-monitoring",
        resource_name="prometheus-k8s",
        client=None,
    ):
        self.namespace = namespace
        self.resource_name = resource_name
        self.client = client or get_client()
        self.api_v1 = "/api/v1"

        # get route to prometheus HTTP api
        self.api_url = self._get_route()

        # get prometheus ServiceAccount token
        self.headers = self._get_headers()

    def _get_route(self):
        # get route to prometheus HTTP api
        LOGGER.info("Prometheus: Obtaining route")
        route = Route(
            namespace=self.namespace, name=self.resource_name, client=self.client
        ).instance.spec.host

        return f"https://{route}"

    def _get_headers(self):
        """Uses the Prometheus serviceaccount to get an access token for OAuth"""
        LOGGER.info("Prometheus: Setting headers")

        LOGGER.info("Prometheus headers: Obtaining OAuth token")

        # get SA
        prometheus_sa = ServiceAccount(
            namespace=self.namespace, name=self.resource_name, client=self.client
        )

        # get secret
        secret_name = prometheus_sa.instance.imagePullSecrets[0].name
        secret = Secret(namespace=self.namespace, name=secret_name, client=self.client)

        # get token value
        token = secret.instance.metadata.annotations["openshift.io/token-secret.value"]

        return {"Authorization": f"Bearer {token}"}

    def _get_response(self, query):
        requests.packages.urllib3.disable_warnings()
        response = requests.get(
            f"{self.api_url}{query}", headers=self.headers, verify=False
        )

        try:
            return json.loads(response.content)
        except JSONDecodeError as json_exception:
            LOGGER.error(
                "Exception converting query response to JSON: "
                f"exc={json_exception} response_status_code={response.status_code} response={response.content}"
            )
            raise

    def query(self, query):
        return self._get_response(query=f"{self.api_v1}/query?query={query}")

    def get_alert(self, alert):
        query = f'ALERTS{{alertname="{alert}"}}'
        return self.query(query=query)["data"]["result"]

    def alert_sampler(self, alert):
        sampler = TimeoutSampler(
            wait_timeout=TIMEOUT_10MIN,
            sleep=1,
            func=self.get_alert,
            alert=alert,
        )
        sample = None
        try:
            for sample in sampler:
                if sample and sample[0]["value"][-1] == "1":
                    return
        except TimeoutExpiredError:
            LOGGER.error(
                f"Failed to get successful alert {alert}. Current data: {sample}"
            )
            raise

    def query_sampler(self, query, timeout=TIMEOUT_10MIN, sleep=1):
        sampler = TimeoutSampler(
            wait_timeout=timeout,
            sleep=sleep,
            func=self.query,
            query=query,
        )
        sample = None
        try:
            for sample in sampler:
                result = sample["data"]["result"]
                LOGGER.info(f"Prometheus Query: {query}: Result: {result}")
                if sample["status"] == "success":
                    return result
        except TimeoutExpiredError:
            LOGGER.error(
                f"Failed to get successful status after executing query '{query}'. Current data: {sample}"
            )
            raise

    @property
    def alerts(self):
        return self._get_response(query=f"{self.api_v1}/alerts")


def wait_for_ssh_connectivity(vm, timeout=TIMEOUT_2MIN, tcp_timeout=TIMEOUT_1MIN):
    LOGGER.info(f"Wait for {vm.name} SSH connectivity.")

    for sample in TimeoutSampler(
        wait_timeout=timeout,
        sleep=5,
        func=vm.ssh_exec.run_command,
        command=["exit"],
        tcp_timeout=tcp_timeout,
    ):
        if sample:
            return


def wait_for_console(vm, console_impl):
    with console_impl(vm=vm, timeout=TIMEOUT_25MIN):
        LOGGER.info(f"Successfully connected to {vm.name} console")


def generate_dict_from_yaml_template(stream, **kwargs):
    """
    Generate YAML from yaml template.

    Args:
        stream (io.StringIO): Yaml file content.

    Returns:
        dict: Generated from template file

    Raises:
        MissingTemplateVariables: If not all template variables exists
    """
    data = stream.read()
    # Find all template variables
    template_vars = [i.split()[1] for i in re.findall(r"{{ .* }}", data)]
    for var in template_vars:
        if var not in kwargs.keys():
            raise MissingTemplateVariables(var=var, template=data)
    template = jinja2.Template(data)
    out = template.render(**kwargs)
    return yaml.safe_load(out)


class MissingTemplateVariables(Exception):
    def __init__(self, var, template):
        self.var = var
        self.template = template

    def __str__(self):
        return f"Missing variables {self.var} for template {self.template}"


def wait_for_windows_vm(vm, version, timeout=TIMEOUT_25MIN):
    """
    Samples Windows VM; wait for it to complete the boot process.
    """

    LOGGER.info(
        f"Windows VM {vm.name} booting up, "
        f"will attempt to access it up to {round(timeout / 60)} minutes."
    )

    sampler = TimeoutSampler(
        wait_timeout=timeout,
        sleep=15,
        func=vm.ssh_exec.run_command,
        command=shlex.split("wmic os get Caption /value"),
    )
    for sample in sampler:
        if version in str(sample):
            return True


# TODO: Remove once bug 1945703 is fixed
def get_guest_os_info(vmi):
    sampler = TimeoutSampler(
        wait_timeout=TIMEOUT_6MIN,
        sleep=5,
        func=lambda: vmi.instance.status.guestOSInfo,
    )

    try:
        for sample in sampler:
            if sample.get("id"):
                return dict(sample)
    except TimeoutExpiredError:
        LOGGER.error("VMI doesn't have guest agent data")
        raise


def get_windows_os_dict(windows_version):
    windows_os_dict = [
        os_dict
        for win_os in py_config["system_windows_os_matrix"]
        for os_name, os_dict in win_os.items()
        if os_name == windows_version
    ]
    if windows_os_dict:
        return windows_os_dict[0]
    raise KeyError(f"Failed to extract {windows_version} from system_windows_os_matrix")


def get_rhel_os_dict(rhel_version):
    rhel_os_dict = [
        os_dict
        for rhel_os in py_config["system_rhel_os_matrix"]
        for os_name, os_dict in rhel_os.items()
        if os_name == rhel_version
    ]
    if rhel_os_dict:
        return rhel_os_dict[0]
    raise KeyError(f"Failed to extract {rhel_version} from system_rhel_os_matrix")


def running_vm(
    vm,
    wait_for_interfaces=True,
    check_ssh_connectivity=True,
    ssh_timeout=TIMEOUT_2MIN,
    wait_for_cloud_init=False,
):
    """
    Wait for the VMI to be in Running state.

    Args:
        vm (VirtualMachine): VM object.
        wait_for_interfaces (bool): Is waiting for VM's interfaces mandatory for declaring VM as running.
        check_ssh_connectivity (bool): Enable SSh service in the VM.
        ssh_timeout (int): how much time to wait for SSH connectivity
        wait_for_cloud_init (bool): Is waiting for cloud-init required.

    Returns:
        VirtualMachine: VM object.
    """
    # For VMs from common templates
    start_vm_timeout = wait_until_running_timeout = TIMEOUT_4MIN

    # For VMs from common templates (Linux and Windows based)
    if vm.is_vm_from_template:
        # Windows 10 takes longer to start
        start_vm_timeout = (
            2600
            if "windows10" in vm.labels[f"{Resource.ApiGroup.VM_KUBEVIRT_IO}/template"]
            else 2100
        )

    # To support all use cases of: 'running'/'runStrategy', container/VM from template, VM started outside this function
    allowed_vm_start_exceptions_dict = {
        ApiException: [
            "Always does not support manual start requests",
            "VM is already running",
            "Internal error occurred: unable to complete request: stop/start already underway",
        ],
    }
    try:
        vm.start(wait=True, timeout=start_vm_timeout)
    except tuple(allowed_vm_start_exceptions_dict) as exception:
        matched_exception = False
        if any(
            [
                message in exception.body
                for message in allowed_vm_start_exceptions_dict[type(exception)]
            ]
        ):
            LOGGER.warning(f"VM {vm.name} is already running; will not be started.")
            matched_exception = True
            # Need to increase how much time we wait for a VMI in case a VM is started before calling this function
            # and has a DV which is cloned from another DV
            vm_printable_status = vm.printable_status
            LOGGER.info(f"VM Status: {vm_printable_status}")
            if not vm_printable_status or vm_printable_status in [
                VirtualMachine.Status.WAITING_FOR_VOLUME_BINDING,
                VirtualMachine.Status.STOPPED,
                VirtualMachine.Status.PROVISIONING,
            ]:
                wait_until_running_timeout = start_vm_timeout

        if not matched_exception:
            raise exception

    # Verify the VM was started (either in this function or before calling it).
    vm.vmi.wait_until_running(timeout=wait_until_running_timeout)

    if wait_for_interfaces:
        wait_for_vm_interfaces(vmi=vm.vmi)

    if check_ssh_connectivity:
        wait_for_ssh_connectivity(vm=vm, timeout=ssh_timeout)

    if wait_for_cloud_init:
        wait_for_cloud_init_complete(vm=vm)
    return vm


def wait_for_cloud_init_complete(vm, timeout=TIMEOUT_4MIN):
    cloud_init_status = "cloud-init status"
    for sample in TimeoutSampler(
        wait_timeout=timeout,
        sleep=5,
        func=vm.ssh_exec.run_command,
        command=shlex.split(cloud_init_status),
    ):
        if not sample[0] and "done" in sample[1]:
            return True
        LOGGER.warning(f"{cloud_init_status} command output {sample}")


def migrate_vm_and_verify(
    vm,
    timeout=TIMEOUT_12MIN,
    wait_for_interfaces=True,
    check_ssh_connectivity=False,
    wait_for_migration_success=True,
):
    """
    create a migration instance. You may choose to wait for migration
    success or not.

    Args:
        vm (VirtualMachine): vm to be migrated
        wait_for_migration_success (boolean):
            True = full teardown will be applied.
            False = no teardown (responsibility on the programmer), and no
                    wait for migration process to finish.

    Returns:
        VirtualMachineInstanceMigration: if wait_for_migration_success == false

    Raises:
        AssertionError: if migration ended with SUCCEEDED status, but node was
                        not changed for migrated vm OR migrationState was not
                        completed.
    """
    node_before = vm.vmi.node
    vmi_source_pod = vm.vmi.virt_launcher_pod

    LOGGER.info(f"VMI {vm.vmi.name} is running on {node_before.name} before migration.")
    with VirtualMachineInstanceMigration(
        name=vm.name,
        namespace=vm.namespace,
        vmi=vm.vmi,
        teardown=wait_for_migration_success,
    ) as migration:
        if not wait_for_migration_success:
            return migration
        wait_for_migration_finished(vm=vm, migration=migration, timeout=timeout)

    verify_vm_migrated(
        vm=vm,
        node_before=node_before,
        vmi_source_pod=vmi_source_pod,
        wait_for_interfaces=wait_for_interfaces,
        check_ssh_connectivity=check_ssh_connectivity,
    )


def wait_for_migration_finished(vm, migration, timeout=TIMEOUT_12MIN):
    migration.wait_for_status(status=migration.Status.SUCCEEDED, timeout=timeout)
    if vm.instance.spec.template.spec.evictionStrategy == LIVE_MIGRATE:
        verify_one_pdb_per_vm(vm=vm)


def verify_vm_migrated(
    vm,
    node_before,
    vmi_source_pod,
    wait_for_interfaces=True,
    check_ssh_connectivity=False,
):
    vmi_name = vm.vmi.name
    vmi_node_name = vm.vmi.node.name
    assert (
        vmi_node_name != node_before.name
    ), f"VMI: {vmi_name} still running on the same node: {vmi_node_name}"

    assert (
        vm.vmi.instance.status.migrationState.completed
    ), f"VMI {vmi_name} migration state is: {vm.vmi.instance.status.migrationState}"
    if wait_for_interfaces:
        wait_for_vm_interfaces(vmi=vm.vmi)

    if check_ssh_connectivity:
        wait_for_ssh_connectivity(vm=vm)


def vm_cloud_init_volume(vm_spec):
    cloud_init_volume = [
        vol
        for vol in vm_spec.setdefault("volumes", [])
        if vol["name"] == CLOUD_INIT_DISK_NAME
    ]

    if cloud_init_volume:
        return cloud_init_volume[0]

    # If cloud init volume needs to be added
    vm_spec["volumes"].append({"name": CLOUD_INIT_DISK_NAME})
    return vm_spec["volumes"][-1]


def vm_cloud_init_disk(vm_spec):
    disks_spec = (
        vm_spec.setdefault("domain", {})
        .setdefault("devices", {})
        .setdefault("disks", [])
    )

    if not [disk for disk in disks_spec if disk["name"] == CLOUD_INIT_DISK_NAME]:
        disks_spec.append({"disk": {"bus": "virtio"}, "name": CLOUD_INIT_DISK_NAME})

    return vm_spec


def prepare_cloud_init_user_data(section, data):
    """
    Generates userData dict to be used with cloud init and add data under the required section.

    section (str): key name under userData
    data: value to be added under "section" key
    """
    cloud_init_data = defaultdict(dict)
    cloud_init_data["userData"][section] = data

    return cloud_init_data


@contextmanager
def vm_instance_from_template(
    request,
    unprivileged_client,
    namespace,
    data_source=None,
    data_volume_template=None,
    existing_data_volume=None,
    cloud_init_data=None,
    node_selector=None,
    vm_cpu_model=None,
    disable_sha2_algorithms=False,
    vm_cpu_flags=None,
):
    """Create a VM from template and start it (start step could be skipped by setting
    request.param['start_vm'] to False.

    Prerequisite - a DV must be created prior to VM creation.

    Args:
        data_source (obj `DataSource`): DS object points to a golden image PVC.
        data_volume_template (dict): dataVolumeTemplates dict; will replace dataVolumeTemplates in VM yaml
        existing_data_volume (obj `DataVolume`: DV resource): existing DV to be consumed directly (not cloned)
        disable_sha2_algorithms (bool, default=False): disable openSSH rsa-sha2-256, rsa-sha2-512 algorithms
            when creating a ssh connection

    Yields:
        obj `VirtualMachine`: VM resource

    """
    params = request.param if hasattr(request, "param") else request
    vm_name = params["vm_name"].replace(".", "-").lower()
    with utilities.infra.cluster_resource(VirtualMachineForTestsFromTemplate)(
        name=vm_name,
        namespace=namespace.name,
        client=unprivileged_client,
        labels=Template.generate_template_labels(**params["template_labels"]),
        data_source=data_source,
        data_volume_template=data_volume_template,
        existing_data_volume=existing_data_volume,
        vm_dict=params.get("vm_dict"),
        cpu_cores=params.get("cpu_cores"),
        cpu_threads=params.get("cpu_threads"),
        memory_requests=params.get("memory_requests"),
        network_model=params.get("network_model"),
        network_multiqueue=params.get("network_multiqueue"),
        cloud_init_data=cloud_init_data,
        attached_secret=params.get("attached_secret"),
        node_selector=node_selector,
        diskless_vm=params.get("diskless_vm"),
        cpu_model=params.get("cpu_model") or vm_cpu_model,
        cpu_flags=params.get("cpu_flags") or vm_cpu_flags,
        cpu_placement=params.get("cpu_placement"),
        isolate_emulator_thread=params.get("isolate_emulator_thread"),
        iothreads_policy=params.get("iothreads_policy"),
        dedicated_iothread=params.get("dedicated_iothread"),
        ssh=params.get("ssh", True),
        disk_options_vm=params.get("disk_io_option"),
        host_device_name=params.get("host_device_name"),
        gpu_name=params.get("gpu_name"),
        cloned_dv_size=params.get("cloned_dv_size"),
        systemctl_support="rhel-6" not in vm_name,
        vhostmd=params.get("vhostmd"),
        machine_type=params.get("machine_type"),
        disable_sha2_algorithms=disable_sha2_algorithms,
        eviction=params.get("eviction", False),
    ) as vm:
        if params.get("start_vm", True):
            running_vm(
                vm=vm,
                wait_for_interfaces=params.get("guest_agent", True),
                check_ssh_connectivity=vm.ssh,
            )
        yield vm


@contextmanager
def node_mgmt_console(admin_client, node, node_mgmt):
    hco_namespace = get_hco_namespace(admin_client=admin_client)
    try:
        LOGGER.info(f"{node_mgmt.capitalize()} the node {node.name}")
        extra_opts = (
            "--delete-local-data --ignore-daemonsets=true --force"
            if node_mgmt == "drain"
            else ""
        )
        run(
            f"nohup oc adm {node_mgmt} {node.name} {extra_opts} &",
            shell=True,
        )
        yield
    finally:
        if node_mgmt == "drain":
            LOGGER.info("Terminate drain process")
            run(
                shlex.split('pkill -f "oc adm drain"'),
            )
        LOGGER.info(f"Uncordon node {node.name}")
        run(f"oc adm uncordon {node.name}", shell=True)
        wait_for_node_schedulable_status(node=node, status=True)
        wait_for_kv_stabilize(admin_client=admin_client, hco_namespace=hco_namespace)


def wait_for_node_schedulable_status(node, status, timeout=60):
    """
    Wait for node status to be ready (status=True) or unschedulable (status=False)
    """
    LOGGER.info(
        f"Wait for node {node.name} to be {Node.Status.READY if status else Node.Status.SCHEDULING_DISABLED}."
    )

    sampler = TimeoutSampler(
        wait_timeout=timeout, sleep=1, func=lambda: node.instance.spec.unschedulable
    )
    for sample in sampler:
        if status:
            if not sample and not kubernetes_taint_exists(node):
                return
        else:
            if sample and kubernetes_taint_exists(node):
                return


def get_hyperconverged_kubevirt(admin_client, hco_namespace):
    for kv in KubeVirt.get(
        dyn_client=admin_client,
        namespace=hco_namespace.name,
        name="kubevirt-kubevirt-hyperconverged",
    ):
        return kv


def get_kubevirt_hyperconverged_spec(admin_client, hco_namespace):
    return get_hyperconverged_kubevirt(
        admin_client=admin_client, hco_namespace=hco_namespace
    ).instance.to_dict()["spec"]


def get_hyperconverged_ovs_annotations(hyperconverged):
    return (hyperconverged.instance.to_dict()["metadata"].get("annotations", {})).get(
        "deployOVS"
    )


def get_base_templates_list(client):
    """Return SSP base templates"""
    common_templates_list = list(
        Template.get(
            dyn_client=client,
            singular_name=Template.singular_name,
            label_selector=Template.Labels.BASE,
        )
    )
    return [
        template
        for template in common_templates_list
        if not template.instance.metadata.annotations.get(
            template.Annotations.DEPRECATED
        )
    ]


def verify_one_pdb_per_vm(vm):
    """Verify one PodDisruptionBudget created for a VM; VM must be configured with evictionStrategy: LiveMigrate

    Args:
        vm (VirtualMachine): VM object

    Raises:
        AssertionError if there is more than one PDB for the VM
    """
    pdb_resource_name = "PodDisruptionBudget"
    LOGGER.info(f"Verify one {pdb_resource_name} for VM {vm.name}")
    pdbs_dict = {}
    for pdb in PodDisruptionBudget.get(dyn_client=get_client(), namespace=vm.namespace):
        if pdb.instance.metadata.ownerReferences[0].name == vm.name:
            pdbs_dict[pdb.name] = pdb.instance.metadata

    assert (
        len(pdbs_dict) == 1
    ), f"VM {vm.name} must have one {pdb_resource_name}, current: {pdbs_dict}"


def assert_pod_status_completed(source_pod):
    source_pod.wait_for_status(status=Pod.Status.SUCCEEDED, timeout=TIMEOUT_3MIN)
    assert (
        source_pod.instance.status.containerStatuses[0].state.terminated.reason
        == Pod.Status.COMPLETED
    )


def get_template_by_labels(admin_client, template_labels):
    template = list(
        Template.get(
            dyn_client=admin_client,
            singular_name=Template.singular_name,
            namespace="openshift",
            label_selector=",".join(
                [
                    f"{label}=true"
                    for label in template_labels
                    if OS_FLAVOR_FEDORA not in label
                ]
            ),
        ),
    )
    if any(
        f"{Template.ApiGroup.OS_TEMPLATE_KUBEVIRT_IO}/{OS_FLAVOR_FEDORA}"
        in template_label
        for template_label in template_labels
    ):
        template = [
            fedora_template
            for fedora_template in template
            if OS_FLAVOR_FEDORA in fedora_template.name
        ]
    matched_templates = len(template)
    assert (
        matched_templates == 1
    ), f"{matched_templates} templates found which match {template_labels} labels"

    return template[0]


def wait_for_updated_kv_value(admin_client, hco_namespace, path, value, timeout=15):
    """
    Waits for updated values in KV CR configuration

    Args:
        admin_client (:obj:`DynamicClient`): DynamicClient object
        hco_namespace (:obj:`Namespace`): HCO namespace object
        path (list): list of nested keys to be looked up in KV CR configuration dict
        value (any): the expected value of the last key in path
        timeout (int): timeout in seconds

    Example:
        path - ['minCPUModel'], value - 'Haswell-noTSX'
        {"configuration": {"minCPUModel": "Haswell-noTSX"}} will be matched against KV CR spec.

    Raises:
        TimeoutExpiredError: After timeout is reached if the expected key value does not match the actual value
    """
    base_path = ["configuration"]
    base_path.extend(path)
    samples = TimeoutSampler(
        wait_timeout=timeout,
        sleep=1,
        func=lambda: benedict(
            get_kubevirt_hyperconverged_spec(
                admin_client=admin_client, hco_namespace=hco_namespace
            ),
            keypath_separator=None,
        ).get(base_path),
    )
    try:
        for sample in samples:
            if sample and sample == value:
                break
    except TimeoutExpiredError:
        hco_annotations = utilities.infra.get_hyperconverged_resource(
            client=admin_client, hco_ns_name=hco_namespace.name
        ).instance.metadata.annotations
        LOGGER.error(
            f"KV CR is not updated, path: {path}, expected value: {value}, HCO annotations: {hco_annotations}"
        )
        raise
    # After updating KV need to be sure HCO is stable
    wait_for_hco_conditions(
        admin_client=admin_client,
        hco_namespace=hco_namespace,
    )


def check_migration_process_after_node_drain(dyn_client, source_pod, vm):
    """
    Wait for migration process to succeed and verify that VM indeed moved to new node.
    """
    source_node = source_pod.node
    LOGGER.info(f"The VMI was running on {source_node.name}")
    wait_for_node_schedulable_status(node=source_node, status=False)
    for migration_job in VirtualMachineInstanceMigration.get(
        dyn_client=dyn_client, namespace=vm.namespace
    ):
        if migration_job.instance.spec.vmiName == vm.name:
            migration_job.wait_for_status(
                status=migration_job.Status.SUCCEEDED, timeout=TIMEOUT_30MIN
            )

    assert_pod_status_completed(source_pod=source_pod)
    target_pod = vm.vmi.virt_launcher_pod
    target_pod.wait_for_status(status=Pod.Status.RUNNING, timeout=TIMEOUT_3MIN)
    verify_one_pdb_per_vm(vm=vm)
    target_node = target_pod.node
    LOGGER.info(f"The VMI is currently running on {target_node.name}")
    assert (
        target_node != source_node
    ), f"Target node is same as source node: {source_node.name}"


def restart_vm_wait_for_running_vm(
    vm, wait_for_interfaces=True, check_ssh_connectivity=True, ssh_timeout=TIMEOUT_2MIN
):
    vm.restart(wait=True)
    # Calling running_vm() to ensure the VM is up and connective
    return running_vm(
        vm=vm,
        wait_for_interfaces=wait_for_interfaces,
        check_ssh_connectivity=check_ssh_connectivity,
        ssh_timeout=ssh_timeout,
    )


def wait_for_kubevirt_conditions(
    admin_client,
    hco_namespace,
    expected_conditions=None,
    wait_timeout=TIMEOUT_10MIN,
    sleep=5,
    consecutive_checks_count=3,
    condition_key1="type",
    condition_key2="status",
):
    """
    Checking Kubevirt status.conditions
    """
    utilities.infra.wait_for_consistent_resource_conditions(
        dynamic_client=admin_client,
        namespace=hco_namespace.name,
        expected_conditions=expected_conditions or DEFAULT_KUBEVIRT_CONDITIONS,
        resource_kind=KubeVirt,
        condition_key1=condition_key1,
        condition_key2=condition_key2,
        total_timeout=wait_timeout,
        polling_interval=sleep,
        consecutive_checks_count=consecutive_checks_count,
    )


def get_all_virt_pods_with_running_status(dyn_client, hco_namespace):
    virt_pods_with_status = {
        pod.name: pod.status
        for pod in Pod.get(
            dyn_client=dyn_client,
            namespace=hco_namespace.name,
        )
        if pod.name.startswith("virt")
    }
    assert all(
        pod_status == Pod.Status.RUNNING
        for pod_status in virt_pods_with_status.values()
    ), (
        f"All virt pods were expected to be in running state."
        f"Here are all virt pods:{virt_pods_with_status}"
    )
    return virt_pods_with_status


def wait_for_kv_stabilize(admin_client, hco_namespace):
    wait_for_kubevirt_conditions(admin_client=admin_client, hco_namespace=hco_namespace)
    wait_for_hco_conditions(admin_client=admin_client, hco_namespace=hco_namespace)


def get_oc_image_info(image, pull_secret=None):
    command_out = None
    base_command = f"oc image -o json info {image}"
    if pull_secret:
        base_command = f"{base_command} --registry-config={pull_secret}"

    try:
        for sample in TimeoutSampler(
            wait_timeout=10,
            sleep=1,
            exceptions_dict={JSONDecodeError: [], TypeError: []},
            func=run_command,
            command=shlex.split(base_command),
        ):
            command_out = sample[1]
            return json.loads(command_out)
    except TimeoutExpiredError:
        LOGGER.error(f"Failed to parse {base_command} output. {command_out}")
        raise


def taint_node_no_schedule(node):
    return ResourceEditor(
        patches={
            node: {
                "spec": {
                    "taints": [
                        {
                            "effect": "NoSchedule",
                            "key": f"{Resource.ApiGroup.KUBEVIRT_IO}/drain",
                            "value": "draining",
                        }
                    ]
                }
            }
        }
    )
