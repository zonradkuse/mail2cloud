from handlers.BaseHandler import BaseHandler

import ftplib
import io
import os
from urllib.parse import urlparse


class FTPHandler(BaseHandler):

    def __init__(self):
        super(FTPHandler, self).__init__()
        self.ssl = False
        self.encoding = "utf-8"

    def applies(self, destination):
        return urlparse(destination).scheme.lower() == "ftp"

    def do_write(self, destination, data):
        self._logger.info("Uploading file via ftp(s).")

        # determine url parts
        parsed_url = urlparse(destination)
        bind_addr = parsed_url.netloc
        username = os.environ["FTP_USERNAME"]
        password = os.environ["FTP_PASSWORD"]

        if self.ssl:
            sess = ftplib.FTP_TLS(bind_addr, username, password)
        else:
            sess = ftplib.FTP(bind_addr, username, password)

        sess.encoding = 'utf-8'
        sess.storbinary(f'STOR {parsed_url.path}', io.BytesIO(data))
        sess.quit()

