from ocp_resources.virtual_machine_cluster_instance_types import (
    VirtualMachineClusterInstancetype,
)
from ocp_resources.virtual_machine_cluster_preferences import (
    VirtualMachineClusterPreference,
)
from ocp_resources.virtual_machine_instance_types import VirtualMachineInstancetype
from ocp_resources.virtual_machine_preferences import VirtualMachinePreference


class InstanceTypeCommonFunctionClass:
    """Class for functions sharing the same functions of cluster/instanceType"""

    def __init__(self):
        if type(self) is InstanceTypeCommonFunctionClass:
            raise NotImplementedError(
                "InstanceTypeCommonFunctionClass is an abstract class and cannot be instantiated directly, You can use "
                "it by creating the VirtualMachineInstanceTypeForTest/VirtualMachineClusterInstanceTypeForTest class"
            )

    def to_dict(self):
        # Will call Resource/NamespacedResource function depending on the inherited class:
        # VirtualMachineInstanceTypeForTest/VirtualMachineClusterInstanceTypeForTest
        super().to_dict()
        instance_type_spec = {
            "cpu": {"guest": self.cpu_cores},
            "memory": {"guest": self.memory_requests},
        }
        self.add_optional_spec(instance_type_spec=instance_type_spec)
        self.res["spec"] = instance_type_spec

    def add_optional_spec(self, instance_type_spec):
        if self.dedicated_cpu_placement is not None:
            instance_type_spec["cpu"][
                "dedicatedCPUPlacement"
            ] = self.dedicated_cpu_placement
        if self.cpu_model:
            instance_type_spec["cpu"]["model"] = self.cpu_model
        if self.cpu_isolate_emulator_thread is not None:
            instance_type_spec["cpu"][
                "isolateEmulatorThread"
            ] = self.cpu_isolate_emulator_thread
        if self.cpu_numa:
            instance_type_spec["cpu"]["numa"] = self.cpu_numa
        if self.cpu_realtime:
            instance_type_spec["cpu"]["realtime"] = self.cpu_realtime
        if self.gpus_list:
            instance_type_spec["gpus"] = self.gpus_list
        if self.host_devices_list:
            instance_type_spec["hostDevices"] = self.host_devices_list
        if self.io_thread_policy:
            instance_type_spec["ioThreadsPolicy"] = self.io_thread_policy
        if self.launch_security:
            instance_type_spec["launchSecurity"] = self.launch_security
        if self.memory_huge_pages:
            instance_type_spec["memory"]["hugepages"] = self.memory_huge_pages


class VirtualMachineInstanceTypeForTest(
    InstanceTypeCommonFunctionClass, VirtualMachineInstancetype
):
    def __init__(
        self,
        name,
        namespace,
        cpu_cores,
        memory_requests,
        dedicated_cpu_placement=None,
        cpu_model=None,
        cpu_isolate_emulator_thread=None,
        cpu_numa=None,
        cpu_realtime=None,
        gpus_list=None,
        host_devices_list=None,
        io_thread_policy=None,
        launch_security=None,
        memory_huge_pages=None,
    ):
        self.cpu_cores = cpu_cores
        self.memory_requests = memory_requests
        self.dedicated_cpu_placement = dedicated_cpu_placement
        self.cpu_model = cpu_model
        self.cpu_isolate_emulator_thread = cpu_isolate_emulator_thread
        self.cpu_numa = cpu_numa
        self.cpu_realtime = cpu_realtime
        self.gpus_list = gpus_list
        self.host_devices_list = host_devices_list
        self.io_thread_policy = io_thread_policy
        self.launch_security = launch_security
        self.memory_huge_pages = memory_huge_pages
        super().__init__(name=name, namespace=namespace)


class VirtualMachineClusterInstanceTypeForTest(
    InstanceTypeCommonFunctionClass, VirtualMachineClusterInstancetype
):
    def __init__(
        self,
        name,
        cpu_cores,
        memory_requests,
        dedicated_cpu_placement=None,
        cpu_model=None,
        cpu_isolate_emulator_thread=None,
        cpu_numa=None,
        cpu_realtime=None,
        gpus_list=None,
        host_devices_list=None,
        io_thread_policy=None,
        launch_security=None,
        memory_huge_pages=None,
    ):
        self.cpu_cores = cpu_cores
        self.memory_requests = memory_requests
        self.dedicated_cpu_placement = dedicated_cpu_placement
        self.cpu_model = cpu_model
        self.cpu_isolate_emulator_thread = cpu_isolate_emulator_thread
        self.cpu_numa = cpu_numa
        self.cpu_realtime = cpu_realtime
        self.gpus_list = gpus_list
        self.host_devices_list = host_devices_list
        self.io_thread_policy = io_thread_policy
        self.launch_security = launch_security
        self.memory_huge_pages = memory_huge_pages
        super().__init__(name=name)


class VirtualMachinePreferenceCommonFunctionClass:
    def __init__(self):
        if type(self) == VirtualMachinePreferenceCommonFunctionClass:
            raise NotImplementedError(
                "VirtualMachinePreferenceCommonFunctionClass is an abstract class and cannot be instantiated directly, "
                "You can use it by creating the "
                "VirtualMachinePreferenceForTest/VirtualMachineClusterPreferenceForTest class"
            )

    def to_dict(self):
        # Will call Resource/NamespacedResource function depending on the inherited class:
        # VirtualMachinePreferenceForTest/VirtualMachineClusterPreferenceForTest
        super().to_dict()
        if not self.yaml_file:
            vm_preference_spec = {}
            self.add_optional_spec(vm_preference_spec=vm_preference_spec)
            self.res["spec"] = vm_preference_spec

    def add_optional_spec(self, vm_preference_spec):
        if self.clock_timezone or self.clock_utc_seconds_offset:
            vm_preference_spec["clock"] = {
                "preferredClockOffset": {
                    "timezone": self.clock_timezone,
                    "utc": {"offsetSeconds": self.clock_utc_seconds_offset},
                }
            }
        if self.clock_preferred_timer:
            vm_preference_spec["preferredTimer"] = self.clock_preferred_timer
        if self.cpu_topology:
            vm_preference_spec["cpu"] = {"preferredCPUTopology": self.cpu_topology}
        if self.devices:
            vm_preference_spec["devices"] = self.devices
        if self.features:
            vm_preference_spec["features"] = self.features
        if self.firmware:
            vm_preference_spec["firmware"] = self.firmware
        if self.machine:
            vm_preference_spec["machine"] = self.machine


class VirtualMachinePreferenceForTest(
    VirtualMachinePreferenceCommonFunctionClass, VirtualMachinePreference
):
    def __init__(
        self,
        name,
        namespace,
        client=None,
        teardown=True,
        yaml_file=None,
        clock_timezone=None,
        clock_utc_seconds_offset=None,
        clock_preferred_timer=None,
        cpu_topology=None,
        devices=None,
        features=None,
        firmware=None,
        machine=None,
        **kwargs,
    ):
        self.clock_timezone = clock_timezone
        self.clock_utc_seconds_offset = clock_utc_seconds_offset
        self.clock_preferred_timer = clock_preferred_timer
        self.cpu_topology = cpu_topology
        self.devices = devices
        self.features = features
        self.firmware = firmware
        self.machine = machine
        super(VirtualMachinePreference, self).__init__(
            name=name,
            namespace=namespace,
            client=client,
            teardown=teardown,
            yaml_file=yaml_file,
            **kwargs,
        )


class VirtualMachineClusterPreferenceForTest(
    VirtualMachinePreferenceCommonFunctionClass, VirtualMachineClusterPreference
):
    def __init__(
        self,
        name,
        client=None,
        teardown=True,
        yaml_file=None,
        clock_timezone=None,
        clock_utc_seconds_offset=None,
        clock_preferred_timer=None,
        cpu_topology=None,
        devices=None,
        features=None,
        firmware=None,
        machine=None,
        preference_spec_file_to_load=None,
        **kwargs,
    ):
        self.clock_timezone = clock_timezone
        self.clock_utc_seconds_offset = clock_utc_seconds_offset
        self.clock_preferred_timer = clock_preferred_timer
        self.cpu_topology = cpu_topology
        self.devices = devices
        self.features = features
        self.firmware = firmware
        self.machine = machine
        self.preference_spec_file_to_load = preference_spec_file_to_load
        super(VirtualMachineClusterPreference, self).__init__(
            name=name, client=client, teardown=teardown, yaml_file=yaml_file, **kwargs
        )
