import multiprocessing
from multiprocessing import Process


class UtilityPodNotFoundError(Exception):
    def __init__(self, node):
        self.node = node

    def __str__(self):
        return f"Utility pod not found for node: {self.node}"


class CommonNodesCpusNotFoundError(Exception):
    def __init__(self, nodes):
        self.nodes = [node.name for node in nodes]

    def __str__(self):
        return f"No common CPU models found across the nodes: {self.nodes}"


class ResourceValueError(Exception):
    pass


class ResourceMissingFieldError(Exception):
    pass


class MissingEnvironmentVariableError(Exception):
    pass


# code from https://stackoverflow.com/questions/19924104/python-multiprocessing-handling-child-errors-in-parent
class ProcessWithException(Process):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._pconn, self._cconn = multiprocessing.Pipe()
        self._exception = None

    def run(self):
        try:
            super().run()
            self._cconn.send(None)
        except Exception as e:
            self._cconn.send(e)
            raise e

    @property
    def exception(self):
        if self._pconn.poll():
            self._exception = self._pconn.recv()
        return self._exception
