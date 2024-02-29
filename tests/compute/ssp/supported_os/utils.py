from utilities.ssp import guest_agent_version_parser


def get_linux_guest_agent_version(ssh_exec):
    ssh_exec.sudo = True
    return guest_agent_version_parser(
        version_string=ssh_exec.package_manager.info("qemu-guest-agent")
    )


def check_qemu_guest_agent_installed(ssh_exec):
    ssh_exec.sudo = True
    return ssh_exec.package_manager.exist(package="qemu-guest-agent")
