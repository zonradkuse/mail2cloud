# mail2cloud

Receives mail attachments and uploads them to a specified target.

## Usecase
Imagine you have a scanner that is able to send scanned documents via e-mail and you would like to
upload those automatically into Nextcloud or similar services automatically.

Or you simply want a mailbox that is only watched for attachments.

NB! This tool does not support Nextcloud directly. Instead, add an external_storage like a ftp share
where you can upload documents.

# Usage

Install the requirements using pip and run `mail2cloud.py`. This will show you more information 
on how to use this program.

```
# python mail2cloud.py -h

usage: mail2cloud.py [-h] [--v] [--service] [--additionally-save-raw-emails]
                     [--user USER] [--password PASSWORD] [--ssl-disabled]
                     [--no-check-certificate-host] [--no-verify-certificate]
                     host target

positional arguments:
  host                  Mail host to check for arriving attachments.
  target                Destination to copy to. By default this is a os file
                        path. Specify the protocol for any other method. For
                        example ftps://<>.

optional arguments:
  -h, --help            show this help message and exit
  --v                   Enable debug log.
  --service             Run mail2cloud as a service and continuously check for
                        arriving attachments.
  --additionally-save-raw-emails
                        Save all arriving emails in a thunderbird readable
                        format to the target.
  --user USER           Mail user. os.environ[MAIL_USER] if absent.
  --password PASSWORD   Mail password. os.environ[MAIL_PASSWORD] if absent.
  --ssl-disabled        Disable IMAP SSL/TLS entirely. Don't do this!
  --no-check-certificate-host
                        Don't check the IMAP certificate host.
  --no-verify-certificate
                        Don't verify the server certificate.

example usage:

      FTP_USER=<> FTP_PASSWORD=<> MAIL_USER=<> MAIL_PASSWORD=<> python mail2cloud.py mail.yourhost ftps://ftp.yourhost/youdirectory
      MAIL_USER=<> MAIL_PASSWORD=<> python mail2cloud.py mail.yourhost /tmp
```

You can run this as a service as well. A respective systemd file might look like this.
```
Type=simple
WorkingDirectory={{mail2cloud_directory}}

Environment="FTP_USERNAME={{mail2cloud_ftp_username}}"
Environment="FTP_PASSWORD={{mail2cloud_ftp_password}}"
Environment="MAIL_USER={{mail2cloud_mail_mailbox}}"
Environment="MAIL_PASSWORD={{mail2cloud_mail_password}}"

ExecStart={{mail2cloud_directory}}/.env/bin/python mail2cloud.py {{mail2cloud_mail_host}} {{mail2cloud_target}} --service --additionally-save-raw-emails

Restart=on-failure

[Install]
WantedBy=multi-user.target
```

# Handlers
Currently there is only a FTP(S) handler implemented. If FTP is not applicable the file will 
be saved locally.

# Contribute
Fork - Commit - Pull Request - Merge

