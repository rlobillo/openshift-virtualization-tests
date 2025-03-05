FROM quay.io/fedora/fedora:40 AS builder

ARG POETRY_HOME='/usr/local'

ENV LANG=C.UTF-8 \
    CNV_TESTS_CONTAINER=Yes \
    PATH="${POETRY_HOME}/bin:/mnt/host:${PATH}"

RUN dnf update -y \
  && dnf -y install \
  systemd-container \
  python3-devel \
  gcc \
  sshpass \
  libcurl-devel \
  libxslt-devel \
  libxml2-devel \
  which \
  && dnf clean all \
  && rm -rf /var/cache/dnf \
  && rm -rf /var/lib/dnf \
  && truncate -s0 /var/log/*.log


COPY / cnv-tests/
WORKDIR cnv-tests

# We should pin poetry to a specific version as recommended by the docs for CI usage.
# but we like to leave on the edge :)
RUN python3 -m pip install pip --upgrade \
    && python3 -m venv ${POETRY_HOME} \
    && ${POETRY_HOME}/bin/pip install pip --upgrade \
    && ${POETRY_HOME}/bin/pip install poetry \
    && ${POETRY_HOME}/bin/pip install poetry-plugin-export \
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

# The following is the runner section, which we start again from a clean Fedora image
# and only adding the required bits to allow us to run the tests.
FROM quay.io/fedora/fedora:40 AS runner

ARG POETRY_HOME='/usr/local'
ARG OPENSHIFT_PYTHON_WRAPPER_COMMIT=''
ARG OPENSHIFT_PYTHON_UTILITIES_COMMIT=''

ENV LANG=C.UTF-8 \
    CNV_TESTS_CONTAINER=Yes \
    PATH="${POETRY_HOME}/bin:/cnv-tests/.venv/bin:/mnt/host:${PATH}" \
    POETRY_HOME=/usr/local

WORKDIR /cnv-tests

COPY --from=builder /cnv-tests/ /cnv-tests/
COPY --from=builder /root/.config/pypoetry/ /root/.config/pypoetry/
COPY --from=builder ${POETRY_HOME} ${POETRY_HOME}

##TODO: We can remove wget, and use curl instead, this will require to change some tests
RUN dnf update -y \
    && dnf install -y \
    procps-ng \
    python3 \
    bind-utils \
    jq \
    fwknop \
    parallel \
    wget \
    clang \
    cargo \
    rsync \
    openssl \
    openssl-devel \
    git \
    && dnf clean all \
    && rm -rf /var/cache/dnf \
    && rm -rf /var/lib/dnf \
    && rm -rf /cnv-tests/cache \
    && rm -rf /root/.cache \
    && truncate -s0 /var/log/*.log \
    && echo "export PATH=${PATH}" | tee /etc/profile.d/poetry.sh \
    && chmod 0644 /etc/profile.d/poetry.sh

CMD ${POETRY_HOME}/bin/poetry run pytest --tc=server_url:"${HTTP_IMAGE_SERVER}" --collect-only
