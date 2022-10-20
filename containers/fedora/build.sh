#!/usr/bin/env bash
set -xe

BUILD_DIR="fedora_build"
FEDORA_IMAGE=$1
CLOUD_INIT_ISO="cidata.iso"
NAME="fedora${FEDORA_VERSION}"
FEDORA_CONTAINER_IMAGE="localhost/fedora:${FEDORA_VERSION}"

IMAGE_BUILD_CMD=$(which podman 2>/dev/null || which docker)

mkdir $BUILD_DIR

echo "Create cloud-init user data ISO"
cloud-localds $CLOUD_INIT_ISO user-data

echo "Run the VM (ctrl+] to exit)"
virt-install \
  --memory 2048 \
  --vcpus 2 \
  --name $NAME \
  --disk $FEDORA_IMAGE,device=disk \
  --disk $CLOUD_INIT_ISO,device=cdrom \
  --os-variant $NAME \
  --virt-type kvm \
  --graphics none \
  --network default \
  --import

echo "Remove Fedora VM"
virsh destroy $NAME || :
virsh undefine $NAME

rm -rf $CLOUD_INIT_ISO

echo "Snapshot image"
qemu-img convert -c -O qcow2 $FEDORA_IMAGE $BUILD_DIR/$FEDORA_IMAGE

echo "Create Dockerfile"

cat <<EOF > "${BUILD_DIR}/Dockerfile"
FROM scratch
COPY --chown=107:107 ${FEDORA_IMAGE} /disk/
EOF

pushd $BUILD_DIR
echo "Build docker image"
${IMAGE_BUILD_CMD} build -t "${FEDORA_CONTAINER_IMAGE}" .

echo "Save docker image as TAR"
${IMAGE_BUILD_CMD} save --output "fedora-${FEDORA_VERSION}.tar" "${FEDORA_CONTAINER_IMAGE}"
popd
echo "Fedora image located in ${BUILD_DIR}/"
