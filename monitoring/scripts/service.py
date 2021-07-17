#!/usr/bin/env python
import os
import shlex
import sqlite3
import subprocess
import sys
import time

# TODO: important, add logger
ALERTS_PATH = os.path.expanduser('~/alerts.txt')
LOGS_PATH = os.path.expanduser('~/logs.txt')


def alert(msg):
    os.system('echo {} >> {}'.format(msg, ALERTS_PATH))


def connect_db(db_path, autocommit=False):
    try:
        if autocommit:
            # If isolation_level is None, it will leave the underlying sqlite3
            # library operating in autocommit mode
            # Ref.: https://bit.ly/2mg5Hie
            conn = sqlite3.connect(db_path, isolation_level=None)
        else:
            conn = sqlite3.connect(db_path)
    except sqlite3.Error:
        raise
    else:
        return conn


def create_db(db_filepath, schema_filepath, overwrite_db=False):
    log('Creating database...')
    db_filepath = os.path.expanduser(db_filepath)
    schema_filepath = os.path.expanduser(schema_filepath)
    db_exists = os.path.exists(db_filepath)

    if overwrite_db and db_exists:
        os.remove(db_filepath)

    retcode = 0
    if not db_exists or overwrite_db:
        try:
            with sqlite3.connect(db_filepath) as conn:
                f = open(schema_filepath, 'rt')
                schema = f.read()
                conn.executescript(schema)
                f.close()
        except (IOError, sqlite3.OperationalError) as e:
            # logger.error("<color>{}</color>".format(get_error_msg(e)))
            log(e)
            raise
        else:
            # logger.info('Database created!')
            log('Database created!')
    else:
        # logger.warning("Database '{}' already exists!".format(db_filepath))
        log("Database '{}' already exists!".format(db_filepath))
        retcode = 1
    return retcode


def log(msg):
    os.system('echo {} >> {}'.format(msg, LOGS_PATH))


def main():
    log('Starting!')
    number_of_args = 2
    if len(sys.argv) == number_of_args or True:
        # configs_path = sys.argv[1]
        configs_path = os.path.expanduser('~/mac-monitoring')
        sys.path.append(configs_path)
        import config
        sleeping = 2
        last = '520m'
        while True:
            log('Executing log command')
            cmd = "log show --last {} --style syslog --predicate \'{}\'".format(
                    last, config.predicate)
            try:
                result = subprocess.check_output(shlex.split(cmd),
                                                 stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                log('Error with log command!')
                sys.exit(1)
            result = result.decode()
            # Don't include first '\n' which is for the row "Timestamp (process)[PID]"
            failed_login_counts = result.count('\n') - 1
            if failed_login_counts:
                alert('ALERT: {} failed login detected!'.format(failed_login_counts))
            else:
                log('Nothing to report!')
            log('Sleeping for {} seconds'.format(sleeping))
            time.sleep(sleeping)
    else:
        log('Wrong number ({}) of arguments. There should be {} arguments'.format(
            len(sys.argv), number_of_args))
    log('Ending! Very odd!')
    sys.exit(0)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt as e:
        log('Ctrl+c detected!')
