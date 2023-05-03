# -*- coding: utf-8 -*-
import logging
import shlex

import bitmath
from ocp_resources.pod_disruption_budget import PodDisruptionBudget
from ocp_resources.resource import ResourceEditor
from ocp_resources.secret import Secret
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from ocp_utilities.utils import run_ssh_commands

from tests.compute.contants import DISK_SERIAL, RHSM_SECRET_NAME
from tests.compute.virt.constants import VIRT_PROCESS_MEMORY_LIMITS
from utilities.constants import RHSM_PASSWD, RHSM_USER, TIMEOUT_5MIN, TIMEOUT_10SEC
from utilities.infra import base64_encode_str, cluster_resource
from utilities.virt import (
    migrate_vm_and_verify,
    prepare_cloud_init_user_data,
    restart_vm_wait_for_running_vm,
    wait_for_ssh_connectivity,
)


LOGGER = logging.getLogger(__name__)
OS_PROC_NAME = {"linux": "ping", "windows": "powershell.exe"}


def get_linux_timezone(ssh_exec):
    return run_ssh_commands(
        host=ssh_exec, commands=shlex.split("timedatectl show | grep -i timezone")
    )[0]


def get_windows_timezone(ssh_exec, get_standard_name=False):
    """
    Args:
        ssh_exec: vm SSH executor
        get_standard_name (bool, default False): If True, get only Windows StandardName
    """
    standard_name_cmd = '| findstr "StandardName"' if get_standard_name else ""
    timezone_cmd = shlex.split(
        f'powershell -command "Get-TimeZone {standard_name_cmd}"'
    )
    return run_ssh_commands(host=ssh_exec, commands=[timezone_cmd])[0]


def start_and_fetch_processid_on_windows_vm(vm, process_name):
    wait_for_ssh_connectivity(vm=vm)
    run_ssh_commands(
        host=vm.ssh_exec,
        commands=shlex.split(f"wmic process call create {process_name}"),
    )
    return fetch_pid_from_windows_vm(vm=vm, process_name=process_name)


def fetch_pid_from_windows_vm(vm, process_name):
    cmd = shlex.split(
        rf"wmic process where (Name=\'{process_name}\') get processid /value"
    )
    cmd_res = run_ssh_commands(host=vm.ssh_exec, commands=cmd)[0].strip()
    assert cmd_res, f"Process '{process_name}' not found in output: {cmd_res}"
    return int(cmd_res.split("=")[-1])


def validate_pause_optional_migrate_unpause_windows_vm(
    vm, pre_pause_pid=None, migrate=False
):
    proc_name = OS_PROC_NAME["windows"]
    if not pre_pause_pid:
        pre_pause_pid = start_and_fetch_processid_on_windows_vm(
            vm=vm, process_name=proc_name
        )
    pause_optional_migrate_unpause_and_check_connectivity(vm=vm, migrate=migrate)
    post_pause_pid = fetch_pid_from_windows_vm(vm=vm, process_name=proc_name)
    kill_processes_by_name_windows(vm=vm, process_name=proc_name)
    assert (
        post_pause_pid == pre_pause_pid
    ), f"PID mismatch!\nPre pause PID is: {pre_pause_pid}\nPost pause PID is: {post_pause_pid}"


def start_and_fetch_processid_on_linux_vm(vm, process_name, args="", use_nohup=False):
    wait_for_ssh_connectivity(vm=vm)
    nohup_cmd = "nohup" if use_nohup else ""
    run_ssh_commands(
        host=vm.ssh_exec,
        commands=shlex.split(
            f"killall -9 {process_name}; {nohup_cmd} {process_name} {args} </dev/null &>/dev/null &"
        ),
    )
    return fetch_pid_from_linux_vm(vm=vm, process_name=process_name)


def fetch_pid_from_linux_vm(vm, process_name):
    cmd_res = run_ssh_commands(
        host=vm.ssh_exec,
        commands=shlex.split(f"pgrep {process_name} || true"),
    )[0].strip()
    assert cmd_res, f"VM {vm.name}, '{process_name}' process not found"
    return int(cmd_res)


def pause_optional_migrate_unpause_and_check_connectivity(vm, migrate=False):
    vm.vmi.pause(wait=True)
    if migrate:
        migrate_vm_and_verify(
            vm=vm, wait_for_interfaces=False, check_ssh_connectivity=False
        )
    vm.vmi.unpause(wait=True)
    wait_for_ssh_connectivity(vm=vm)


def validate_pause_optional_migrate_unpause_linux_vm(
    vm, pre_pause_pid=None, migrate=False
):
    proc_name = OS_PROC_NAME["linux"]
    if not pre_pause_pid:
        pre_pause_pid = start_and_fetch_processid_on_linux_vm(
            vm=vm, process_name=proc_name, args="localhost"
        )
    pause_optional_migrate_unpause_and_check_connectivity(vm=vm, migrate=migrate)
    post_pause_pid = fetch_pid_from_linux_vm(vm=vm, process_name=proc_name)
    kill_processes_by_name_linux(vm=vm, process_name=proc_name)
    assert (
        post_pause_pid == pre_pause_pid
    ), f"PID mismatch!\nPre pause PID is: {pre_pause_pid}\nPost pause PID is: {post_pause_pid}"


def validate_libvirt_persistent_domain(vm):
    domain = vm.vmi.virt_launcher_pod.execute(
        command=shlex.split("virsh list --persistent"), container="compute"
    )
    assert vm.vmi.Status.RUNNING.lower() in domain


def kill_processes_by_name_linux(vm, process_name, check_rc=True):
    cmd = shlex.split(f"pkill {process_name}")
    run_ssh_commands(host=vm.ssh_exec, commands=cmd, check_rc=check_rc)


def kill_processes_by_name_windows(vm, process_name):
    cmd = shlex.split(f"taskkill /F /IM {process_name}")
    run_ssh_commands(host=vm.ssh_exec, commands=cmd)


def verify_pods_priority_class_value(pods, expected_value):
    failed_pods_list = [
        pod.name
        for pod in pods
        if pod.instance.spec["priorityClassName"] != expected_value
    ]
    assert (
        not failed_pods_list
    ), f"priorityClassName not set correctly in pods: {failed_pods_list}, should be {expected_value}"


def verify_no_listed_alerts_on_cluster(prometheus, alerts_list):
    """
    It gets a list of alerts and verifies that none of them are firing on a cluster.
    """
    fired_alerts = {}
    for alert in alerts_list:
        alert_state = prometheus.get_alert(alert=alert)
        if alert_state and alert_state[0]["metric"]["alertstate"] == "firing":
            fired_alerts[alert] = alert_state

    assert (
        not fired_alerts
    ), f"Alerts should not be fired on healthy cluster.\n {fired_alerts}"


def generate_rhsm_cloud_init_data():
    bootcmds = [
        f"mkdir /mnt/{RHSM_SECRET_NAME}",
        f'mount /dev/$(lsblk --nodeps -no name,serial | grep {DISK_SERIAL} | cut -f1 -d" ") /mnt/{RHSM_SECRET_NAME}',
        "subscription-manager config --rhsm.auto_enable_yum_plugins=0",
    ]

    return prepare_cloud_init_user_data(section="bootcmd", data=bootcmds)


def generate_rhsm_secret(namespace):
    with cluster_resource(Secret)(
        name=RHSM_SECRET_NAME,
        namespace=namespace.name,
        data_dict={
            "username": base64_encode_str(text=RHSM_USER),
            "password": base64_encode_str(text=RHSM_PASSWD),
        },
    ) as secret:
        yield secret


def register_vm_to_rhsm(vm):
    LOGGER.info("Register the VM with RedHat Subscription Manager")

    run_ssh_commands(
        host=vm.ssh_exec,
        commands=shlex.split(
            "sudo subscription-manager register "
            "--serverurl=subscription.rhsm.stage.redhat.com:443/subscription "
            "--baseurl=https://cdn.stage.redhat.com "
            f"--username=`sudo cat /mnt/{RHSM_SECRET_NAME}/username` "
            f"--password=`sudo cat /mnt/{RHSM_SECRET_NAME}/password` "
            "--auto-attach"
        ),
    )


def generate_attached_rhsm_secret_dict():
    return {
        "volume_name": "rhsm-secret-vol",
        "serial": DISK_SERIAL,
        "secret_name": RHSM_SECRET_NAME,
    }


def get_pod_disruption_budget(admin_client, namespace_name):
    return list(
        PodDisruptionBudget.get(
            dyn_client=admin_client,
            namespace=namespace_name,
        )
    )


def has_kubevirt_owner(resource):
    return any(
        [
            owner_reference.apiVersion.startswith(f"{resource.ApiGroup.KUBEVIRT_IO}/")
            for owner_reference in resource.instance.metadata.get("ownerReferences", [])
        ]
    )


def check_pod_disruption_budget_for_completed_migrations(
    admin_client, namespace, timeout=TIMEOUT_5MIN
):
    samples = TimeoutSampler(
        wait_timeout=timeout,
        sleep=TIMEOUT_10SEC,
        func=get_pod_disruption_budget,
        admin_client=admin_client,
        namespace_name=namespace,
    )
    pod_disruption_budget_desired_states = None
    try:
        for sample in samples:
            pod_disruption_budget_desired_states = {
                pdb.name: pdb.instance.spec.minAvailable
                for pdb in sample
                if has_kubevirt_owner(resource=pdb)
                and pdb.instance.spec.minAvailable > 1
            }
            # Return if there are no more required migrations
            if not pod_disruption_budget_desired_states:
                return
    except TimeoutExpiredError:
        LOGGER.error(
            f"Some migrations are still created: {pod_disruption_budget_desired_states}"
        )
        raise


def assert_vm_xml_efi(vm, secure_boot_enabled=True):
    LOGGER.info("Verify VM XML - EFI secureBoot values.")
    xml_dict_os = vm.vmi.xml_dict["domain"]["os"]
    ovmf_path = "/usr/share/OVMF"
    efi_path = f"{ovmf_path}/OVMF_CODE.secboot.fd"
    # efi vars path when secure boot is enabled: /usr/share/OVMF/OVMF_VARS.secboot.fd
    # efi vars path when secure boot is disabled: /usr/share/OVMF/OVMF_VARS.fd
    efi_vars_path = (
        f"{ovmf_path}/OVMF_VARS.{'secboot.' if secure_boot_enabled else ''}fd"
    )
    vmi_xml_efi_path = xml_dict_os["loader"]["#text"]
    vmi_xml_efi_vars_path = xml_dict_os["nvram"]["@template"]
    vmi_xml_os_secure = xml_dict_os["loader"]["@secure"]
    os_secure = "yes" if secure_boot_enabled else "no"
    assert (
        vmi_xml_efi_path == efi_path
    ), f"EFIPath value {vmi_xml_efi_path} does not match expected {efi_path} value"
    assert (
        vmi_xml_os_secure == os_secure
    ), f"EFI secure value {vmi_xml_os_secure} does not seem to be set as {os_secure}"
    assert (
        vmi_xml_efi_vars_path == efi_vars_path
    ), f"EFIVarsPath value {vmi_xml_efi_vars_path} does not match expected {efi_vars_path} value"


def assert_linux_efi(vm):
    """
    Verify guest OS is using EFI.
    """
    run_ssh_commands(host=vm.ssh_exec, commands=["ls", "-ld", "/sys/firmware/efi"])


def assert_windows_efi(vm):
    """
    Verify guest OS is using EFI.
    """
    out = run_ssh_commands(
        host=vm.ssh_exec, commands=shlex.split("bcdedit | findstr EFI")
    )[0]
    assert (
        "\\EFI\\Microsoft\\Boot\\bootmgfw.efi" in out
    ), f"EFI boot not found in path. bcdedit output:\n{out}"


def update_vm_efi_spec_and_restart(vm, spec=None, wait_for_interfaces=True):
    ResourceEditor(
        {
            vm: {
                "spec": {
                    "template": {
                        "spec": {
                            "domain": {"firmware": {"bootloader": {"efi": spec or {}}}}
                        }
                    }
                }
            }
        }
    ).update()
    restart_vm_wait_for_running_vm(vm=vm, wait_for_interfaces=wait_for_interfaces)


def get_virt_launcher_processes_memory_overuse(pod):
    memory_overuse = {}
    for process in VIRT_PROCESS_MEMORY_LIMITS.keys():
        memory_usage = bitmath.KiB(
            value=int(
                pod.execute(
                    command=shlex.split(
                        f"bash -c 'ps -o rss --no-headers -p $(pidof {process})'"
                    ),
                    container="compute",
                )
            )
        )
        if memory_usage > VIRT_PROCESS_MEMORY_LIMITS[process]:
            memory_overuse[process] = {
                "memory usage": memory_usage,
                "memory limit": VIRT_PROCESS_MEMORY_LIMITS[process],
            }
    return memory_overuse
