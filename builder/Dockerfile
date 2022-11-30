FROM quay.io/centos/centos:stream9
#TODO: remove pipenv commands and exports once our infra move to poetry

ENV PIPENV_VENV_IN_PROJECT=1 \
    CNV_TESTS_CONTAINER=Yes \
    PATH="$PATH:/mnt/host"

ARG OPENSHIFT_PYTHON_WRAPPER_COMMIT
ARG OPENSHIFT_PYTHON_UTILITIES_COMMIT

RUN dnf -y install epel-release \
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
    && dnf clean all

COPY / cnv-tests/
WORKDIR cnv-tests

RUN python3 -m pip install pip --upgrade \
    && python3 -m pip install poetry pipenv \
    && pipenv install --skip-lock \
    && poetry install \
    && poetry export --without-hashes -n \
    && if [[ -n "${OPENSHIFT_PYTHON_WRAPPER_COMMIT}" ]]; then poetry run pip install git+https://github.com/RedHatQE/openshift-python-wrapper.git@$OPENSHIFT_PYTHON_WRAPPER_COMMIT -U; fi \
    && if [[ -n "${OPENSHIFT_PYTHON_UTILITIES_COMMIT}" ]]; then poetry run pip install git+https://github.com/RedHatQE/openshift-python-utilities.git@$OPENSHIFT_PYTHON_UTILITIES_COMMIT -U; fi \
    && if [[ -n "${OPENSHIFT_PYTHON_WRAPPER_COMMIT}" ]]; then pipenv run pip install git+https://github.com/RedHatQE/openshift-python-wrapper.git@$OPENSHIFT_PYTHON_WRAPPER_COMMIT -U; fi \
    && if [[ -n "${OPENSHIFT_PYTHON_UTILITIES_COMMIT}" ]]; then pipenv run pip install git+https://github.com/RedHatQE/openshift-python-utilities.git@$OPENSHIFT_PYTHON_UTILITIES_COMMIT -U; fi

CMD poetry run pytest --tc=server_url:"$HTTP_IMAGE_SERVER" --collect-only
