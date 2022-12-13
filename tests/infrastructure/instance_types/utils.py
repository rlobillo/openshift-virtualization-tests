from ocp_resources.virtual_machine_cluster_instance_types import (
    VirtualMachineClusterInstancetype,
)
from ocp_resources.virtual_machine_cluster_preferences import (
    VirtualMachineClusterPreference,
)

from tests.utils import (
    InstanceTypeCommonFunctionClass,
    VirtualMachinePreferenceCommonFunctionClass,
)


class VirtualMachineClusterInstanceTypeForTest(
    InstanceTypeCommonFunctionClass, VirtualMachineClusterInstancetype
):
    def __init__(
        self,
        name,
        cpu_cores,
        memory_requests,
        client=None,
        teardown=True,
        yaml_file=None,
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
        **kwargs,
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
        super(VirtualMachineClusterInstancetype, self).__init__(
            name=name,
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
