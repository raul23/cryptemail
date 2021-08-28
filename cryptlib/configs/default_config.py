# =========================================================================== #
#                       cryptoemail config options                            #
# =========================================================================== #

# ==============
# Common options
# ==============
# Home directory where the keys (e.g. GnuPG) will be saved
# if homedir is None or ''
homedir = '/path/to/homedir'
asymmetric = {
    # Recipient's fingerprint (for encryption when sending an email)
    'recipient_fingerprint': 'RECIPIENT_FINGERPRINT',
    # Your signature fingerprint
    'signature_fingerprint': 'YOUR_SIGNATURE_FINGERPRINT'
}
# If the passphrase can't be found saved locally, prompt for it
# Passphrase will be used for decryption
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
inbox_address = 'your_inbox@mail.com'

# googleapi can be used both for sending and reading emails
# IMPORTANT: token-based authentication is only supported for gmail addresses
# The use of tokens is more secure than using an email password
googleapi = {
    'sender': {
        'credentials_path': '/path/to/credentials.json',
        # Scopes for the gmail google API
        'scopes': ['https://www.googleapis.com/auth/gmail.modify'],
    },
    'reader': {
        'credentials_path': '/path/to/credentials.json',
        # Scopes for the gmail google API
        'scopes': ['https://www.googleapis.com/auth/gmail.modify'],
    }
}

# tls is used for sending emails
# imap is used for reading emails
smtp = {
    'tls_port': 587,
    'imap_port': 1143,
    'smtp_server': 'smtp.gmail.com',
    # If no email password (e.g. from your gmail account) found saved locally,
    # prompt email password
    'prompt_email_password': True
}

# ==================================
# Sending and reading emails options
# ==================================
# Config options for sending emails
send_emails = {
    # How to connect to the email server: googleapi or smtp
    'connection_method': 'googleapi',
    # FROM and TO information
    'sender_email_address': inbox_address,  # FROM
    'receiver_email_address': 'receiver@mail.com',  # TO
    # Sign and encrypt in a single pass. Otherwise, sign first and then encrypt
    # as separate processes
    'use_single_pass': False,
    # Signature options
    'signature': {
        'program': 'PGP',
        'enable_signature': True,
    },
    # Encryption options
    'encryption': {
        'program': 'PGP',
        'encryption_type': 'asymmetric'
    }
}

# Config options for reading emails
read_emails = {
    # How to connect to the email server for reading emails: googleapi or smtp
    'connection_method': 'googleapi',
    'reader_email_address': inbox_address,
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

# Test connection to an email server either through googleapi, smtp or None
# If None, then no connection testing will done
test_connection = 'googleapi'
