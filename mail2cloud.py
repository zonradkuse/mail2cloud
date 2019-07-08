# supplementary
import argparse
import os
import ssl
import logging
import socket
import io
from urllib.parse import urlparse

# local
from attachment import Attachment
from handlers import FTPHandler, FTPSHandler

# email
import email
from email.policy import SMTPUTF8
from imapclient import IMAPClient, SEEN

import ftplib

_HANDLERS = [FTPHandler(), FTPSHandler()]

def main():
    args = parse_arguments()
    initialise_logger(args)

    logging.getLogger("mail2cloud").info(f"Starting processing for {args.host}")
    imap_connector = connect_imap(args.host, args.user, args.password,
                        ssl_enabled=args.ssl_enabled,
                        host_check=args.host_check,
                        verify_certificate=args.verify_certificate)

    if args.service:
        while True:
            process_inbox(imap_connector, args.target, args.save_raw)
            imap_idle(imap_connector)

    else:
        process_inbox(imap_connector, args.target, args.save_raw)


def process_inbox(imap_connector, destination, save_raw):
    messages_raw = check_unread_mails(imap_connector)

    if len(messages_raw) < 1:
        logging.getLogger("mail2cloud.imap").info("No new messages")
    else:
        messages = [email.message_from_bytes(m[b'RFC822'], policy=SMTPUTF8) for mid, m in messages_raw.items()]
        attachments = extract_all_attachments(messages)
        if save_raw:
            save_source_messages(messages, destination)

        save_attachments(attachments, destination)

        logging.getLogger("mail2cloud").info(f"Finished uploading {len(attachments)} attachments from {len(messages)} messages total.")

        # by now we have checked all new mail so we mark everything as seen
        mark_as_seen(imap_connector, messages_raw)

def imap_idle(imap_connector):
    try:
        imap_connector.idle()
        imap_connector.idle_check(timeout=180)
    except (TimeoutError, socket.error) as e:
        logging.getLogger("mail2cloud").error(f"A network error occured during wait: {e}")
    finally: # make sure to close this in case anything odd happens.
        imap_connector.idle_done()

def parse_arguments():
    epilog='''example usage:

      FTP_USER=<> FTP_PASSWORD=<> MAIL_USER=<> MAIL_PASSWORD=<> python mail2cloud.py mail.yourhost ftps://ftp.yourhost/youdirectory
      MAIL_USER=<> MAIL_PASSWORD=<> python mail2cloud.py mail.yourhost /tmp'''

    parser = argparse.ArgumentParser(epilog=epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('--v', dest='v', action='store_true', help="Enable debug log.")
    parser.add_argument('--service', dest='service', action='store_true', help='Run mail2cloud as a service and continuously check for arriving attachments.')

    parser.add_argument('host', help='Mail host to check for arriving attachments.')
    parser.add_argument('target', help='Destination to copy to. By default this is a os file path. Specify the protocol for any other method. For example ftps://<>.')

    parser.add_argument('--additionally-save-raw-emails', dest='save_raw', action='store_true', help='Save all arriving emails in a thunderbird readable format to the target.')

    parser.add_argument('--user', help='Mail user. os.environ[MAIL_USER] if absent.')
    parser.add_argument("--password", help='Mail password. os.environ[MAIL_PASSWORD] if absent.')
    parser.add_argument('--ssl-disabled', dest='ssl_enabled', action='store_false', help="Disable IMAP SSL/TLS entirely. Don't do this!")
    parser.add_argument('--no-check-certificate-host', dest='host_check', action='store_false', help="Don't check the IMAP certificate host.")
    parser.add_argument('--no-verify-certificate', dest='verify_certificate', action='store_false', help="Don't verify the server certificate.")

    parser.set_defaults(service=False)
    parser.set_defaults(save_raw=False)
    parser.set_defaults(host_check=True)
    parser.set_defaults(verify_certificate=True)
    parser.set_defaults(v=False)
    parser.set_defaults(user=os.environ["MAIL_USER"] if "MAIL_USER" in os.environ else None)
    parser.set_defaults(password=os.environ["MAIL_PASSWORD"] if "MAIL_PASSWORD" in os.environ else None)

    args = parser.parse_args()

    assert(args.password is not None or "MAIL_PASSWORD" in os.environ)

    if args.password is None:
        args.password = os.environ["MAIL_PASSWORD"]

    return parser.parse_args()

def initialise_logger(args):
    level = logging.INFO

    if args.v:
        level = logging.DEBUG

    logging.basicConfig(level=level, format='[%(levelname)s] - %(name)s: %(message)s')

def connect_imap(host, username, password, **kwargs):
    if kwargs.get("ssl_enabled", True):
        ssl_context = ssl.create_default_context()

        if not kwargs.get("host_check", True):
            ssl_context.verify_mode = ssl.CERT_NONE

        if kwargs.get("verify_certificate", True):
            ssl_context.check_hostname = False

        imap = IMAPClient(host, ssl_context=ssl_context)
    else:
        imap = IMAPClient(host)

    imap.login(username, password)
    logging.getLogger("mail2cloud.imap").info(f"Successfully connected to {host}")

    return imap

def check_unread_mails(server):
    select_folder(server)
    messages = server.search('UNSEEN')

    logging.getLogger("mail2cloud.imap").info("Fetching unread messages. This might take a bit...")

    return server.fetch(messages, 'RFC822')

def select_folder(server, ro = True):
    server.select_folder('INBOX', readonly=ro)

def extract_all_attachments(messages):
    result = []
    for message in messages:
        result.extend(get_attachments(message))

    logging.getLogger("mail2cloud").info(f"Fetched a total of {len(result)} attachments.")
    return result

def get_attachments(message):
    result = []
    for raw_attachment in message.iter_attachments():
        if raw_attachment.get_filename() is None:
            continue

        raw_file = raw_attachment.get_payload(decode=True)
        attachment = Attachment(raw_attachment.get_filename(),
                 raw_file,
                 len(raw_file),
                 raw_attachment.get_content_type(),
                 message)

        result.append(attachment)
        logging.getLogger("mail2cloud.imap").info(f"Found attachment {attachment}.")

    return result

def save_source_messages(messages, destination):
    for message in messages:
        base_name = construct_target_filename_base(message)
        write_to_destination(f"{destination}/{base_name}.eml", message.as_bytes())

def save_attachments(attachments, destination):
    for attachment in attachments:
        base_name = construct_target_filename_base(attachment.origin)
        write_to_destination(f"{destination}/{base_name}-{attachment.name}", attachment.data)

def construct_target_filename_base(message):
    timestamp = message.get('Date').datetime.strftime('%Y-%m-%d-%H%M%S')
    return f"{timestamp}-{message.get('From')}-{message.get('Subject')}"

def write_to_destination(full_path, data):
    has_handlers = [handler.applies(full_path) for handler in _HANDLERS]
    if True in has_handlers:
        handler = _HANDLERS[has_handlers.index(True)]
        handler.write(full_path, data)

    else:
        file = open(full_path, 'wb')
        file.write(data)
        file.close()

def mark_as_seen(server, messages):
    select_folder(server, False)
    server.add_flags(messages, [SEEN])


if __name__ == "__main__":
    main()

