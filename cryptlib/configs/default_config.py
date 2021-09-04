# =========================================================================== #
#                       cryptoemail config options                            #
# =========================================================================== #

# ==============
# Common options
# ==============
# Home directory where the keys (e.g. GnuPG) will be saved
homedir = '/path/to/homedir'
asymmetric = {
    # Recipient's USER-ID, e.g. fingerprint
    # For encryption when sending an email
    'recipient_userid': 'RECIPIENT_USERID',
    # Your signature (USER-ID)
    'signature': 'YOUR_SIGNATURE'
}
interactive = False
# If the passphrase can't be found saved locally, prompt for it
# Passphrase will be used for decryption and signing
prompt_passphrase = True

# ===============
# General options
# ===============
quiet = False
verbose = False
logging_level = 'info'
logging_formatter = 'simple'

# =============
# Edit options
# ============
app = None

# ==================
# Connection options
# ==================
mailbox_address = 'your_mailbox@address.com'

# googleapi can be used both for sending and reading emails
# IMPORTANT: token-based authentication is only supported for gmail addresses
# The use of tokens is more secure than using an email password
googleapi = {
    'sender_auth': {
        'credentials_path': '/path/to/credentials.json',
        # Scopes for the gmail google API
        'scopes': ['https://www.googleapis.com/auth/gmail.modify'],
    },
    'reader_auth': {
        'credentials_path': '/path/to/credentials.json',
        # Scopes for the gmail google API
        'scopes': ['https://www.googleapis.com/auth/gmail.modify'],
    }
}

# smtp is used for sending (outgoing) messages
# imap is used for reading (incoming) messages
smtp_imap = {
    'smtp_port': 587,  # tls
    'imap_port': 993,  # tls
    # Outgoing Mail (SMTP) Server
    'smtp_server': 'SMTP_SERVER_NAME',  # e.g. smtp.gmail.com
    # Incoming Mail (IMAP) Server
    'imap_server': 'IMAP_SERVER_NAME',  # e.g. imap.gmail.com
    # If no email password found locally, prompt email password
    'prompt_email_password': True
}

# ==================================
# Sending and reading emails options
# ==================================
# Config options for sending emails
send_emails = {
    # How to connect to the email server: googleapi or smtp_imap
    'connection_method': 'smtp_imap',
    'receiver_email_address': 'receiver@mail.com',
    # Sign and encrypt in a single pass. Otherwise, sign first and then encrypt
    # as separate processes
    'use_single_pass': False,
    # Signature options
    'signature': {
        'program': 'GPG',
        'enable_signature': True,
    },
    # Encryption options
    'encryption': {
        'program': 'GPG',
        'encryption_type': 'asymmetric'
    }
}

# Config options for reading emails
read_emails = {
    # How to connect to the email server for reading emails: googleapi or smtp_imap
    'connection_method': 'googleapi',
    'add_decryption_results': False,
    # Folders for saving emails
    'valid_emails_dirpath': '/path/to/valid/emails/',
    'invalid_emails_dirpath': '/path/to/invalid/emails/',
    'unknown_emails_dirpath': '/path/to/unknown/emails/'
}

# ===============
# Testing options
# ===============
# Test message encryption and decryption
test_encryption = True

# Test message signature
test_signature = True

# Message to be used for testing encryption or signing
test_message = "Hello, World!"

# Test connection to an email server either through googleapi, smtp_imap or None
# If None, then no connection testing will done
test_connection = 'googleapi'
