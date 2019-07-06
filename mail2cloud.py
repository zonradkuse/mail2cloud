import argparse
import os
import ssl
import logging

from attachment import Attachment

import email
from email.policy import SMTPUTF8

from imapclient import IMAPClient

def main():
    args = parse_arguments()
    initialise_logger(args)

    logging.getLogger("mail2cloud").info(f"Starting processing for {args.host}")
    imap_connector = connect_imap(args.host, args.user, args.password,
                        ssl_enabled=args.ssl_enabled,
                        host_check=args.host_check,
                        verify_certificate=args.verify_certificate)

    messages = check_unread_mails(imap_connector)

    if len(messages) < 1:
        logging.getLogger("IMAP").info("No new messages")
    else:
        attachments = extract_all_attachments(messages)
        source_messages = set([att.origin for att in attachments])
        save_source_messages(source_messages, args.target)
        save_attachments(attachments, args.target)

def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument('host', help='mail host to check for arriving attachments')
    parser.add_argument('user', help='mail user')
    parser.add_argument('--service', dest='service', action='store_true', help='run this as a service and continuously check for arriving attachments.')
    parser.add_argument('--ssl-disabled', dest='ssl_enabled', action='store_false', help="Disable SSL entirely. Don't do this!")
    parser.add_argument('--no-check-certificate-host', dest='host_check', action='store_false', help="Don't check the certificate host.")
    parser.add_argument('--no-verify-certificate', dest='verify_certificate', action='store_false', help="Don't verify the server certificate.")
    parser.add_argument('target', help='the destination to copy to. By default this is a os file path. Specify the protocol for any other method, example https, webdav or sftp.')
    parser.add_argument("--password", help='mail password. os.environ[MAIL_PASSWORD] if absent')
    parser.add_argument('--v', dest='v', action='store_true', help="Enable debug log")
    parser.add_argument('--vvv', dest='vvv', action='store_true', help="Enable trace log")

    parser.set_defaults(service=False)
    parser.set_defaults(host_check=True)
    parser.set_defaults(verify_certificate=True)
    parser.set_defaults(v=False)
    parser.set_defaults(vvv=False)
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
    logging.getLogger("IMAP").info(f"Successfully connected to {host}")

    return imap

def check_unread_mails(server):
    server.select_folder('INBOX', readonly=True)
    messages = server.search('UNSEEN')

    logging.getLogger("IMAP").info("Fetching unread messages. This might take a bit...")

    return server.fetch(messages, 'RFC822').items()

def extract_all_attachments(messages):
    result = []
    for uid, message_data in messages:
        email_message = email.message_from_bytes(message_data[b'RFC822'], policy=SMTPUTF8)
        result.extend(get_attachments(email_message))

    logging.getLogger("mail2cloud").info(f"Fetched a total of {len(result)} attachments.")
    return result

def get_attachments(message):
    result = []
    for raw_attachment in message.iter_attachments():
        raw_file = raw_attachment.get_payload(decode=True)
        attachment = Attachment(raw_attachment.get_filename(),
                 raw_file,
                 len(raw_file),
                 raw_attachment.get_content_type(),
                 message)

        result.append(attachment)
        logging.getLogger("IMAP").info(f"Found attachment {attachment}.")

    return result

def save_source_messages(messages, destination):
    for message in messages:
        base_name = construct_target_filename_base(message)
        file = open(f"{destination}/{base_name}.eml", 'wb')
        file.write(message.as_bytes())
        file.close()

def save_attachments(attachments, destination):
    for attachment in attachments:
        base_name = construct_target_filename_base(attachment.origin)
        file = open(f"{destination}/{base_name}-{attachment.name}", 'wb')
        file.write(attachment.data)
        file.close()

def construct_target_filename_base(message):
    return f"{message.get('Date')}-{message.get('From')}-{message.get('Subject')}"

if __name__ == "__main__":
    main()

