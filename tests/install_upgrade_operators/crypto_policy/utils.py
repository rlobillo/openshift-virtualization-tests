import logging

from benedict import benedict
from ocp_utilities.infra import cluster_resource

from tests.install_upgrade_operators.constants import KEY_PATH_SEPARATOR


LOGGER = logging.getLogger(__name__)


def get_resource_crypto_policy(admin_client, resource, name, key_name, namespace=None):
    """
    This function is used to get crypto policy settings associated with a resource

    Args:
        admin_client (DynamicClient): OCP Client to use.
        resource (Resource): Resource kind
        name (str): name of a resource
        key_name (str): full key path with separator
        namespace (str, optional): namespace for the resource

    Returns:
        dict: crypto policy settings value associated with the resource
    """
    kwargs = {"client": admin_client, "name": name}
    if namespace:
        kwargs["namespace"] = namespace
    resource_obj = cluster_resource(resource)(**kwargs)
    return benedict(
        resource_obj.instance.to_dict()["spec"], keypath_separator=KEY_PATH_SEPARATOR
    ).get(key_name)
