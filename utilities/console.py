import logging
import os

import pexpect
from ocp_resources.utils import TimeoutSampler

from utilities.constants import (
    OS_FLAVOR_CENTOS,
    OS_FLAVOR_CIRROS,
    OS_FLAVOR_FEDORA,
    OS_FLAVOR_RHEL,
    OS_LOGIN_PARAMS,
    TIMEOUT_5MIN,
)
from utilities.data_collector import get_data_collector_dict


LOGGER = logging.getLogger(__name__)


class Console(object):
    USERNAME = PASSWORD = None

    def __init__(self, vm, username=None, password=None, timeout=30, prompt=None):
        """
        Connect to VM console

        Args:
            vm (VirtualMachine): VM resource
            username (str): VM username
            password (str): VM password

        Examples:
            from utilities import console
            with console.Fedora(vm=vm) as vmc:
                vmc.sendline('some command)
                vmc.expect('some output')
        """
        self.vm = vm
        self.username = username or self.USERNAME
        self.password = password or self.PASSWORD
        self.timeout = timeout
        self.child = None
        self.login_prompt = "login:"
        self.prompt = prompt if prompt else "#" if self.username == "root" else [r"\$"]
        self.cmd = self._generate_cmd()
        data_collector_dict = get_data_collector_dict()
        self.base_dir = data_collector_dict["data_collector_base_directory"]

    def connect(self):
        LOGGER.info(f"Connect to {self.vm.name} console")
        self.console_eof_sampler(
            func=pexpect.spawn, command=self.cmd, timeout=self.timeout
        )

        self._connect()

        return self.child

    def _connect(self):
        self.child.send("\n\n")
        if self.username:
            self.child.expect(self.login_prompt, timeout=TIMEOUT_5MIN)
            LOGGER.info(f"{self.vm.name}: Using username {self.username}")
            self.child.sendline(self.username)
            if self.password:
                self.child.expect("Password:")
                LOGGER.info(f"{self.vm.name}: Using password {self.password}")
                self.child.sendline(self.password)

        self.child.expect(self.prompt, timeout=150)
        LOGGER.info(f"{self.vm.name}: Got prompt.")

    def disconnect(self):
        if self.child.terminated:
            self.console_eof_sampler(
                func=pexpect.spawn, command=self.cmd, timeout=self.timeout
            )

        self.child.send("\n\n")
        self.child.expect(self.prompt)
        if self.username:
            self.child.send("exit")
            self.child.send("\n\n")
            self.child.expect("login:")
        self.child.close()

    def force_disconnect(self):
        """
        Method is a workaround for RHEL 7.7.
        For some reason, console may not be logged out successfully in __exit__()
        """
        self.console_eof_sampler(
            func=pexpect.spawn, command=self.cmd, timeout=self.timeout
        )
        self.disconnect()

    def console_eof_sampler(self, func, command, timeout):
        sampler = TimeoutSampler(
            wait_timeout=TIMEOUT_5MIN,
            sleep=5,
            func=func,
            exceptions_dict={pexpect.exceptions.EOF: []},
            command=command,
            timeout=timeout,
            encoding="utf-8",
        )
        for sample in sampler:
            if sample:
                self.child = sample
                self.child.logfile = open(
                    f"{self.base_dir}/{self.vm.name}.pexpect.log", "a"
                )
                break

    def _generate_cmd(self):
        virtctl = os.environ.get("VIRTCTL", "virtctl")
        cmd = f"{virtctl} console {self.vm.name}"
        if self.vm.namespace:
            cmd += f" -n {self.vm.namespace}"
        return cmd

    def __enter__(self):
        """
        Connect to console
        """
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Logout from shell
        """
        self.disconnect()


class Fedora(Console):
    params = OS_LOGIN_PARAMS[OS_FLAVOR_FEDORA]
    USERNAME = params["username"]
    PASSWORD = params["password"]


class Cirros(Console):
    params = OS_LOGIN_PARAMS[OS_FLAVOR_CIRROS]
    USERNAME = params["username"]
    PASSWORD = params["password"]


class RHEL(Console):
    params = OS_LOGIN_PARAMS[OS_FLAVOR_RHEL]
    USERNAME = params["username"]
    PASSWORD = params["password"]


class Centos(Console):
    params = OS_LOGIN_PARAMS[OS_FLAVOR_CENTOS]
    USERNAME = params["username"]
    PASSWORD = params["password"]


CONSOLE_IMPL = {
    OS_FLAVOR_RHEL: RHEL,
    OS_FLAVOR_FEDORA: Fedora,
    OS_FLAVOR_CENTOS: Centos,
    OS_FLAVOR_CIRROS: Cirros,
}
