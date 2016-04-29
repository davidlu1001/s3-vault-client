#!/usr/bin/env python
# encoding: utf-8

import sys
import subprocess
import datetime
import yaml
import os
import logging
import argparse
import hashlib
import hmac
import base64
import requests

"""
Please make sure the config file 'vault.yml'
does exist in the following places:

~/.vault.yml
OR
/etc/vault.yml
"""

GLOBAL_KEY_FILE = '/etc/vault.yml'
USER_KEY_FILE = os.path.join(os.environ['HOME'], '.vault.yml')
BASE_URL = 'https://example.com/'
LOG_FILE = '/var/log/vault.log'


def get_configuration():
    """
    Reads the connection/encryption configuration and returns it.

    :return: Dictionary containing the configuration elements.
    """

    try_files = [USER_KEY_FILE, GLOBAL_KEY_FILE]

    for config_file in try_files:
        try:
            config = yaml.load(open(config_file, 'rt').read())
        except yaml.YAMLError as e:
            logging.debug('Config file {} not found/accessible: {}'
                          .format(config_file, str(e)))
        if config:
            break
    if not config:
        logging.error('Could not access a suitable config file.')
        sys.exit(1)

    return config


def get_path(catalog, filename):
    """
    Generate a catalog path based on the current date.

    :return: Path as a string.
    """
    path = os.path.join(catalog,
                        datetime.datetime.now().strftime('%Y/%m/%d'),
                        filename)
    logging.info('File Path: {}'.format(path))

    return path


def get_date():
    """
    Get UTC date header for HTTP request.

    :return: Date formatted as string.
    """
    utc_now = datetime.datetime.utcnow()
    date = utc_now.strftime("%a, %d %b %Y %X +0000")
    logging.info("Generate UTC Time Header: "+ date)

    return str(date)


def execute_gpg_encryption(filename, config):

    # Encrypt with GnuPG
    command = ['gpg',
               '--symmetric',
               '--cipher-algo',
               config['gpg']['algorithm'],
               '--passphrase-fd', '0',
               '--batch',
               filename]

    suffix = '.gpg'
    filename_gpg = "".join((filename, suffix))

    try:
        # Python2 version for compatibility
        p = subprocess.Popen(command,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        p_result = p.communicate(input=config['gpg']['key'])
        logging.debug('Output of encryption for file {}: {}'
                      .format(filename, p_result[0]))

    except subprocess.CalledProcessError as e:
        logging.error('Encryption has exited with error code {}: {}'
                      .format(e.returncode, e.output))
        sys.exit(1)

    return filename_gpg


def execute_gpg_decryption(filename_gpg, config):

    """
    Decrypt filename_gpg file with $PASSPHRASE set in config

    :param filename_gpg: encrypted filename with suffix '.gpg'
    :param config: vault.yml
    :return: decrypted original file
    """

    command = ['gpg', filename_gpg]

    try:
        p = subprocess.Popen(command,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        p_result = p.communicate(input=config['gpg']['key'])
        logging.debug('Output of decryption for file {}: {}'
                      .format(filename_gpg, p_result[0]))

    except subprocess.CalledProcessError as e:
        logging.error('Decryption has exited with error code {}: {}'
                      .format(e.returncode, e.output))
        sys.exit(1)


    filename, file_extension = os.path.splitext(filename_gpg)

    if file_extension == '.gpg':
        return filename
    else:
        logging.error('file has unexpected suffix, please check.')
        return filename_gpg


def execute_put_request(filename, path, bucket, config):
    """
    Generate file checksum and signature for HTTP PUT requests.

    :return: requests.Response
    """

    content_type = 'application/octet-stream'
    file_checksum = base64.standard_b64encode(
        hashlib.md5(open(filename, 'rb').read()).digest())
    logging.info("Generate file checksum: {}".format(file_checksum))
    date = get_date()
    message = '\n'.join(['PUT', file_checksum, content_type, date,
                         '/{}/{}'.format(bucket, path)])
    full_url = os.path.join(BASE_URL, bucket, path)
    logging.info("Generate message: {}".format(message))
    signature = base64.standard_b64encode(
        hmac.HMAC(config['vault']['secret_key'].encode('utf-8'),
                  msg=message.encode('utf-8'),
                  digestmod=hashlib.sha1).digest())
    logging.info("Generate signature: {}".format(signature))
    headers = {
        'Date': date,
        'Authorization': ('AWS {}:{}'
                          .format(config['vault']['access_key'],
                                  signature)),
        'Content-MD5': file_checksum,
        'Content-Type': content_type,
    }

    try:
        r = requests.put(full_url,
                         data=open(filename, 'rb'),
                         headers=headers)
        logging.info("HTTP PUT request url: {}, response: {}"
                     .format(full_url, r.status_code))

    except requests.exceptions.RequestException as e:
        logging.exception("HTTP PUT request FAILED with {}"
                          .format(filename))
        sys.exit(1)

    return r


def execute_get_request(filename_gpg, path, bucket, config):
    """
    Download file via HTTP GET requests.

    :return: requests.Response
    """

    #content_type = 'application/octet-stream'
    #file_checksum = base64.standard_b64encode(
    #    hashlib.md5(open(filename, 'rb').read()).digest())
    #logging.info("Generate file checksum: {}".format(file_checksum))
    date = get_date()
    message = '\n'.join(['GET', date])
    full_url = os.path.join(BASE_URL, bucket, path)
    logging.info("Generate message: {}".format(message))
    signature = base64.standard_b64encode(
        hmac.HMAC(config['vault']['secret_key'].encode('utf-8'),
                  msg=message.encode('utf-8'),
                  digestmod=hashlib.sha1).digest())
    logging.info("Generate signature: {}".format(signature))
    headers = {
        'Date': date,
        'Authorization': ('AWS {}:{}'
                          .format(config['vault']['access_key'],
                                  signature)),
    #    'Content-MD5': file_checksum,
    #    'Content-Type': content_type,
    }

    try:
        r = requests.get(full_url,
                         headers=headers)
        logging.info("HTTP GET request url: {}, response: {}"
                     .format(full_url, r.status_code))

    except requests.exceptions.RequestException as e:
        logging.exception("HTTP GET request FAILED with {}"
                          .format(filename_gpg))
        sys.exit(1)

    return r


#def execute_list_request(bucket, path, config):

def main():
    logging.basicConfig(filename=LOG_FILE,
                        level=logging.INFO,
                        format='%(levelname)s\t%(asctime)s %(message)s')

    # Setup the command line argument parser.

    DESCRIPTION = ('vault upload')
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('bucket', type=str, help='a bucket name, eg. msd-staging-log')
    parser.add_argument('catalog', type=str, help='a catalog name, eg. logstash')
    parser.add_argument('filename', type=str, help='a upload file, eg. beats-2016-04-01.gz')
    args = parser.parse_args()

    # Start upload process
    config = get_configuration()
    filename_gpg = execute_gpg_encryption(args.filename, config)
    path = get_path(args.catalog, filename_gpg)
    #execute_put_request(filename_gpg, path, args.bucket, config)

    # Start download process
    execute_get_request(filename_gpg, path, args.bucket, config)


if __name__ == '__main__':
    main()
