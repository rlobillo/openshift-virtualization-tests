from utilities.infra import get_pods


def validate_metallb_pods_running(admin_client, namespace):
    metallb_not_running_pods = [
        {pod.name: pod.status}
        for pod in get_pods(dyn_client=admin_client, namespace=namespace)
        if pod.name.startswith("metallb-operator")
        and pod.instance.status.phase != pod.Status.RUNNING
    ]

    assert (
        not metallb_not_running_pods
    ), f"MetalLB pods are not in running state. Current: {metallb_not_running_pods}"
