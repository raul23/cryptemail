# =========================================================================== #
#                        cryptemail config options                            #
# =========================================================================== #

# ==============
# Common options
# ==============
# Home directory where the keys are saved (e.g. ~/.gnupg)
homedir = '/path/to/homedir'
interactive = False
prompt_passwords = True

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
# How to connect to the email server: googleapi or smtp_imap
connection_method = 'smtp_imap'

# googleapi can be used both for sending and reading emails
# IMPORTANT: token-based authentication is only supported for gmail addresses
# The use of tokens is more secure than using an email password
googleapi = {
    'credentials_path': '/path/to/credentials.json',
    # Scopes for the gmail google API
    'scopes_for_sending': ['https://www.googleapis.com/auth/gmail.modify'],
    'scopes_for_reading': ['https://www.googleapis.com/auth/gmail.modify'],
}

# smtp is used for sending (outgoing) messages
# imap is used for reading (incoming) messages
smtp_imap = {
    'smtp_port': 587,  # tls
    'imap_port': 993,  # tls
    # Outgoing Mail (SMTP) Server
    'smtp_server': 'SMTP_SERVER_NAME',  # e.g. smtp.gmail.com
    # Incoming Mail (IMAP) Server
    'imap_server': 'IMAP_SERVER_NAME'  # e.g. imap.gmail.com
}

# ==================================
# Sending and reading emails options
# ==================================
# Config options for sending emails
send_emails = {
    'receiver_email_address': 'receiver@mail.com',
    # Sign and encrypt in a single pass. Otherwise, sign first and then encrypt
    # as separate steps
    'use_single_pass': True,
    # Signature options
    'sign': {
        'program': 'GPG',
        'enable_signature': False,
        # Your signature (USER-ID), e.g. fingerprint
        'signature': 'YOUR_SIGNATURE'
    },
    # Encryption options
    'encrypt': {
        'program': 'GPG',
        # Recipient's USER-ID, e.g. fingerprint
        'recipient_userid': 'RECIPIENT_USERID'
    }
}

# Config options for reading emails
read_emails = {
    'add_decryption_results': False,
    # Directory for saving emails
    'emails_dirpath': '/path/to/emails'
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
test_connection = None
