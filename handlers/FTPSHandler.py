from handlers.FTPHandler import FTPHandler

from urllib.parse import urlparse

class FTPSHandler(FTPHandler):

    def __init__(self):
        super(FTPSHandler, self).__init__()
        self.ssl = True

    def applies(self, destination):
        return urlparse(destination).scheme.lower().startswith("ftps")

