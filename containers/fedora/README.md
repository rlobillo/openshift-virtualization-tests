# Prerequisite
Export the relevant Fedora version, fore example:
```bash
export FEDORA_VERSION=32
```

# Fedora VM container

Image can be downloaded from https://alt.fedoraproject.org/cloud/
To create a Fedora VM container execute build.sh.

To execute the build script the following packages needed:

    cloud-utils
    podman or docker (https://docs.docker.com/install/linux/docker-ce/fedora)
    virt-install
    qemu-img

build.sh get Fedora image as parameter, for example:
```bash
export FEDORA_IMAGE=Fedora-Cloud-Base-32-1.6.x86_64.qcow2
./build.sh $FEDORA_IMAGE $FEDORA_VERSION
```

This will install:

    tcpdump
    qemu-guest-agent
    iperf3
    dmidecode
    nginx
    lldpad
    kernel-modules
    nmap
    dhcp
    sshpass
    podman
    ethtool
    libibverbs
    dpdk
    stress-ng
    iotop
    fio

and enable qemu-guest-agent and sshd services in the VM.
If any extra packages/commands are needed, they should be added in user-data file (as part of cloudinit).

Once the OS is up and all packages are installed, you should have a login prompt to the VM.

Shutdown the VM:
```bash
sudo shutdown -h now
```

The tar container will be located under "fedora_build" folder.


### push container
```bash
cd fedora_build
docker load -i fedora-$FEDORA_VERSION.tar
docker tag fedora:$FEDORA_VERSION quay.io/openshift-cnv/qe-cnv-tests-fedora-staging:$FEDORA_VERSION
docker push quay.io/openshift-cnv/qe-cnv-tests-fedora-staging:$FEDORA_VERSION
```

32 tag should be changed based on the Fedora version.

### Verify
Change tests/utilities/manifests/vm-fedora.yaml to use fedora-staging image
`image: quay.io/openshift-cnv/qe-cnv-tests-fedora-staging:<fedora vesion>`
Run the tests (cnv-tests).

Once verified push the image to quay.io/openshift-cnv/qe-cnv-tests-fedora
```bash
docker tag fedora:$FEDORA_VERSION quay.io/openshift-cnv/qe-cnv-tests-fedora:$FEDORA_VERSION
docker push quay.io/openshift-cnv/qe-cnv-tests-fedora:$FEDORA_VERSION
```

Update tests/utilities/manifests/vm-fedora.yaml with the latest OS tag
`image: quay.io/openshift-cnv/qe-cnv-tests-fedora:<fedora vesion>`

### Push qcow image to HTTP servers
Push qcow2 image to EMEA and USA HTTP servers
```bash
scp -i cnv-qe-jenkins.key fedora_build/$FEDORA_IMAGE root@cnv-qe-server.lab.eng.tlv2.redhat.com:/var/www/files/cnv-tests/fedora-images/
scp -i cnv-qe-jenkins.key fedora_build/$FEDORA_IMAGE root@cnv-qe-server.rhevdev.lab.eng.rdu2.redhat.com:/var/www/files/cnv-tests/fedora-images/
```
