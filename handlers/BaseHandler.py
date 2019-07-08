import logging

from abc import ABC, abstractmethod

class BaseHandler(ABC):
    def __init__(self):
        self._logger = logging.getLogger("mail2cloud.handlers." + type(self).__name__)

    def applies(self, url):
        """
        Return a bool

        Checks whether the handler is applicable to the supplied url
        """
        return False

    def write(self, destination, data):
        assert(self.applies(destination))
        self.do_write(destination, data)

    @abstractmethod
    def do_write(self, destination, data):
        """
        Given a destination url perform the write action
        """
        pass

