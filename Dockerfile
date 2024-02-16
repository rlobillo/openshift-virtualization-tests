FROM quay.io/centos/centos:stream9 AS builder

ARG OPENSHIFT_PYTHON_WRAPPER_COMMIT=''
ARG OPENSHIFT_PYTHON_UTILITIES_COMMIT=''
ARG POETRY_HOME='/usr/local'

ENV LANG=C.UTF-8 \
    CNV_TESTS_CONTAINER=Yes \
    PATH="${POETRY_HOME}/bin:/mnt/host:${PATH}"

RUN dnf update -y \
    && dnf -y install epel-release \
    && dnf -y install \
    systemd-container \
    python3-pip \
    python3-devel \
    procps-ng \
    rsync \
    gcc \
    git \
    wget \
    libcurl-devel \
    libxslt-devel \
    libxml2-devel \
    openssl-devel \
    && dnf clean all && rm -rf /var/cache/yum

COPY / cnv-tests/
WORKDIR cnv-tests

# TODO: We should pin poetry to a specific version as recommended by the docs for CI usage.

RUN python3 -m pip install pip --upgrade \
    && python3 -m venv ${POETRY_HOME} \
    && ${POETRY_HOME}/bin/pip install pip --upgrade \
    && ${POETRY_HOME}/bin/pip install poetry \
    && ${POETRY_HOME}/bin/poetry --version \
    && ${POETRY_HOME}/bin/poetry config cache-dir /cnv-tests \
    && ${POETRY_HOME}/bin/poetry config virtualenvs.in-project true \
    && ${POETRY_HOME}/bin/poetry config --list \
    && ${POETRY_HOME}/bin/poetry install \
    && ${POETRY_HOME}/bin/poetry export --without-hashes -n \
    && if [[ -n "${OPENSHIFT_PYTHON_WRAPPER_COMMIT}" ]];   then ${POETRY_HOME}/bin/poetry run pip install git+https://github.com/RedHatQE/openshift-python-wrapper.git@$OPENSHIFT_PYTHON_WRAPPER_COMMIT -U; fi \
    && if [[ -n "${OPENSHIFT_PYTHON_UTILITIES_COMMIT}" ]]; then ${POETRY_HOME}/bin/poetry run pip install git+https://github.com/RedHatQE/openshift-python-utilities.git@$OPENSHIFT_PYTHON_UTILITIES_COMMIT -U; fi \
    && rm -rf /cnv-tests/cache \
    && rm -rf /cnv-tests/artifacts

RUN find /cnv-tests/ -type d -name "__pycache__" -print0 | xargs -0 rm -rfv

# The following is the runner section, which we start again from a clean CentOS9 image
# and only adding the required bits to allow us to run the tests.
FROM quay.io/centos/centos:stream9 AS runner

ARG POETRY_HOME='/usr/local'

ENV LANG=C.UTF-8 \
    CNV_TESTS_CONTAINER=Yes \
    PATH="${POETRY_HOME}/bin:/cnv-tests/.venv/bin:/mnt/host:${PATH}" \
    POETRY_HOME=/usr/local

WORKDIR /cnv-tests

# Add Red Hat IT certificates
ADD https://certs.corp.redhat.com/certs/2015-IT-Root-CA.pem /etc/pki/ca-trust/source/anchors/RH-IT-Root-CA-2015.crt
ADD https://certs.corp.redhat.com/certs/2022-IT-Root-CA.pem /etc/pki/ca-trust/source/anchors/RH-IT-Root-CA-2022.crt
RUN update-ca-trust extract

COPY --from=builder /cnv-tests/ /cnv-tests/
COPY --from=builder /root/.config/pypoetry/ /root/.config/pypoetry/
COPY --from=builder ${POETRY_HOME} ${POETRY_HOME}

##TODO: We can remove wget, and use curl instead, this will require to change some tests
RUN dnf update -y \
    && dnf install -y procps-ng python3 git sshpass jq wget rsync skopeo epel-release \
    && dnf install -y parallel fwknop \
    && dnf clean all \
    && rm -rf /var/cache/yum \
    && rm -rf /var/lib/dnf \
    && rm -rf /cnv-tests/cache \
    && rm -rf /root/.cache \
    && truncate -s0 /var/log/*.log \
    && echo "export PATH=${PATH}" | tee /etc/profile.d/poetry.sh \
    && chmod 0644 /etc/profile.d/poetry.sh

CMD ${POETRY_HOME}/bin/poetry run pytest --tc=server_url:"${HTTP_IMAGE_SERVER}" --collect-only
