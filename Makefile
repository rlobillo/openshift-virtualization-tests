# Pytest args handling
PYTEST_ARGS ?= tests --tc-file=tests/global_config.py --tc-format=python

#OPENSHIFT_PYTHON_WRAPPER LOG LEVEL
export OPENSHIFT_PYTHON_WRAPPER_LOG_LEVEL=DEBUG


# Building cnv-tests container for disconnected clusters
IMAGE_BUILD_CMD = $(shell which podman 2>/dev/null || which docker)
IMAGE_REGISTRY ?= "quay.io"
REGISTRY_NAMESPACE ?= "openshift-cnv"
OPERATOR_IMAGE_NAME="cnv-tests-github"
# Need to change when master point to new version of cnv-tests
IMAGE_TAG ?= "cnv-4.12"

FULL_OPERATOR_IMAGE ?= "$(IMAGE_REGISTRY)/$(REGISTRY_NAMESPACE)/$(OPERATOR_IMAGE_NAME):$(IMAGE_TAG)"
POETRY_BIN = poetry

all: check

check:
	tox

venv-install:
	$(POETRY_BIN) install

build-container:
	$(IMAGE_BUILD_CMD) build --network=host --no-cache -f Dockerfile -t $(FULL_OPERATOR_IMAGE) --build-arg OPENSHIFT_PYTHON_WRAPPER_COMMIT=$(OPENSHIFT_PYTHON_WRAPPER_COMMIT) --build-arg OPENSHIFT_PYTHON_UTILITIES_COMMIT=$(OPENSHIFT_PYTHON_UTILITIES_COMMIT) .

push-container:
	$(IMAGE_BUILD_CMD) push $(FULL_OPERATOR_IMAGE)

build-and-push-container: build-container push-container

.PHONY: \
	check \
	build-container \
	push-container \
	build-and-push-container \
