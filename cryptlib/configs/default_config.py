# =========================================================================== #
#                        cryptemail config options                            #
# =========================================================================== #

# ==============
# Common options
# ==============
# Home directory where the keys are saved (e.g. ~/.gnupg)
homedir = 'WRITEME: /path/to/homedir'
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
# Your mailbox address, e.g. your_email@address.com
mailbox_address = 'WRITEME: your_mailbox@address.com'
# How to connect to the email server: googleapi or smtp_imap
connection_method = 'smtp_imap'

# googleapi can be used both for sending and reading emails
# IMPORTANT: token-based authentication is only supported for gmail addresses
# The use of tokens is more secure than using an email password
googleapi = {
    # Path to the credential
    'credentials_path': 'WRITEME: /path/to/credentials.json',
    # Scopes for the gmail google API
    'scopes_for_sending': ['https://www.googleapis.com/auth/gmail.modify'],
    'scopes_for_reading': ['https://www.googleapis.com/auth/gmail.modify'],
}

# smtp is used for sending (outgoing) messages
# imap is used for reading (incoming) messages
smtp_imap = {
    'smtp_port': 587,  # tls
    'imap_port': 993,  # tls
    # Outgoing Mail (SMTP) Server, e.g. smtp.gmail.com
    'smtp_server': 'WRITEME: SMTP_SERVER_NAME',
    # Incoming Mail (IMAP) Server, e.g. imap.gmail.com
    'imap_server': 'WRITEME: IMAP_SERVER_NAME'
}

# ==================================
# Sending and reading emails options
# ==================================
# Config options for sending emails
send_emails = {
    # Email address of the receiver (aka recipient)
    'receiver_email_address': 'WRITEME: receiver@mail.com',
    # Sign and encrypt in a single pass. Otherwise, sign first and then encrypt
    # as separate steps
    'use_single_pass': True,
    # Signature options
    'sign': {
        'program': 'GPG',
        'enable_signature': False,
        # Your signature (USER-ID) for signing the email, e.g. fingerprint
        'signature': 'WRITEME: YOUR_SIGNATURE'
    },
    # Encryption options
    'encrypt': {
        'program': 'GPG',
        # Recipient's USER-ID for encrypting the email, e.g. fingerprint
        'recipient_userid': 'WRITEME: RECIPIENT_USERID'
    }
}

# Config options for reading emails
read_emails = {
    'add_decryption_results': False,
    # Directory for saving emails
    'emails_dirpath': 'WRITEME: /path/to/emails'
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

# 'emails_dirpath': 'WRITEME: /path/to/emails'
