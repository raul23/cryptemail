# =========================================================================== #
#                       cryptoemail config options                            #
# =========================================================================== #

# ==============
# Common options
# ==============
# Home directory where the keys will be saved
HOMEDIR = '/path/to/homedir'
ASYMMETRIC = {
    'name': 'asymmetric',
    # Fingerprint associated with encryption and decryption
    'encryption_fingerprint': 'YOUR_ENCRYPTION_FINGERPRINT',
    # Fingerprint associated with signature
    'signature_fingerprint': 'YOUR_SIGNATURE_FINGERPRINT'
}
SYMMETRIC = {
    'name': 'symmetric',
    'cipher_algo': 'AES256',
    'digest_algo': 'SHA512',
    'compress_algo': 'default',
    # If no symmetric encryption password found saved locally, prompt password
    'prompt_symmetric_password': True
}
# Use Pinentry Mac for entering your passphrase when generating keys, signing
# or decrypting emails
USE_PINENTRY_MAC = True
# If the passphrase can't be found saved locally, prompt for it
# Passphrase will be used for decryption
PROMPT_PASSPHRASE = True

# ==================
# Connection options
# ==================
# NOTE: both addresses can be the same
SENDER_EMAIL_ADDRESS = 'YOUR_SENDER_EMAIL_ADDRESS'
READER_EMAIL_ADDRESS = 'YOUR_READER_EMAIL_ADDRESS'

# googleapi can be used both for sending and reading emails
# IMPORTANT: token-based authentication is only supported for gmail addresses
# The use of tokens is more secure than using an email password
googleapi = {
    'name': 'googleapi',
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
    'name': 'smtp',
    'tls_port': 587,
    'imap_port': 1143,
    'smtp_server': 'smtp.gmail.com',
    # If no email password (e.g. from your gmail account) found saved locally,
    # prompt email password
    'prompt_email_password': True,
}

# ==================================
# Sending and reading emails options
# ==================================
# Config options for sending emails
send_emails = {
    # How to connect to the email server: googleapi or smtp
    'connection_method': googleapi,
    # FROM and TO information
    'sender_email_address': SENDER_EMAIL_ADDRESS,  # FROM
    'receiver_email_address': READER_EMAIL_ADDRESS,  # TO
    # If keys not found saved locally, prompt the user to enter data useful
    # for generating the keys
    'prompt_generate_keys': True,
    # Use the same encryption keys for signing also.
    # IMPORTANT: it is highly recommended to use separate keys for encrypting
    # and signing
    'reuse_keys': True,
    # Sign and encrypt in a single pass. Otherwise, sign first and then encrypt
    # as separate processes
    'use_single_pass': False,
    # Sign emails
    'signature': {
        'program': 'PGP',
        'enable_signature': True,
    },
    # Encryption options
    # NOTE: the emails in the inbox will remain encrypted and will only be
    # decrypted locally
    'encryption': {
        'program': 'PGP',
        'encryption_type': ASYMMETRIC
    }
}

# Config options for reading emails
read_emails = {
    # How to connect to the email server: googleapi or smtp
    'connection_method': googleapi,
    'reader_email_address': READER_EMAIL_ADDRESS,
    'show_first_unread_emails': 10,
    # Delete emails from the inbox after reading them
    'delete_emails_read': False,
    # If True, every new emails will be saved locally
    'save_emails': False,
    'add_decryption_results': False,
    # Folders for saving emails
    'valid_emails_dirpath': '/path/to/valid/emails/',
    'invaid_emails_dirpath': '/path/to/invalid/emails/',
    'unknown_emails_dirpath': '/path/to/unknown/emails/'
}

# ===============
# Testing options
# ===============
# Test message encryption and decryption
test_encryption = True

# Test message signature
test_signature = True

# Test connection to an email server either through googleapi or smtp
test_connection = googleapi
