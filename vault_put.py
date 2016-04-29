#!/usr/bin/env python
# encoding: utf-8

import sys
import subprocess
import datetime
from datetime import date, timedelta
import yaml
import os
import logging
import argparse
import hashlib
import hmac
import base64
import requests
import time


"""
Please make sure the config file 'vault.yml'
does exist in the following places:

~/.vault.yml
OR
/etc/vault.yml
OR
os.environ["ACCESS_KEY"], os.environ["SECRET_KEY"]
os.environ["algorithm"], os.environ["proxy"]

"""

GLOBAL_KEY_FILE = '/etc/vault.yml'
USER_KEY_FILE = os.path.join(os.environ['HOME'], '.vault.yml')
BASE_URL = 'https://example.com/'
LOG_FILE = '/var/log/vault.log'

# Requests module not used since urllib3 not support https proxy
#proxy_dict = {
#    'http': 'http://1.1.1.1',
#    'https': 'http://1.1.1.1:443',
#}


def get_configuration():
    """
    Reads the connection/encryption configuration and returns it.

    :return: Dictionary containing the configuration elements.
    """

    try_files = [USER_KEY_FILE, GLOBAL_KEY_FILE]
    flag_config_exist = 0

    for config_file in try_files:
        try:
            if os.path.isfile(config_file):
                config = yaml.load(open(config_file, 'rt').read())
                flag_config_exist = 1
            continue
        except yaml.YAMLError as e:
            logging.debug('Config file {} not found/accessible: {}'
                          .format(config_file, str(e)))
        if config:
            break

    if not flag_config_exist:
        logging.error('Could not access a suitable config file.')
	try:
            logging.info('Use setting in os environ: ACCESS: {} SECRET: {}'.format(os.environ["ACCESS_KEY"], os.environ["SECRET_KEY"]))
            return os.environ["ACCESS_KEY"], os.environ["SECRET_KEY"]
        except:
            print("can't find access_keys in anywhere!")

        sys.exit(1)

    return config


def get_path(catalog, filename):
    """
    Generate a catalog path based on the yesterday date.

    :return: Path as a string.
    """
    yesterday = date.today() - timedelta(1)
    path = os.path.join(catalog,
#                        datetime.datetime.now().strftime('%Y/%m/%d'),
                        yesterday.strftime('%Y/%m/%d'),
                        filename)
    logging.info('Upload File Path: {}'.format(path))

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


def execute_put_request(filename, path, bucket, config):
    """
    Generate file checksum and signature for HTTP PUT requests.

    AWS S3 StringToSign Format Example for Request PUT:

    PUT\n
    \n
    image/jpeg\n
    Tue, 27 Mar 2007 21:15:45 +0000\n
    /johnsmith/photos/puppy.jpg

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
        logging.info("Start HTTP PUT request url: {}, proxyies: {}"
                     .format(full_url, proxy_dict))
        r = requests.put(full_url,
                         data=open(filename, 'rb'),
                         headers=headers,
                         proxies=proxy_dict)
        logging.info("HTTP PUT request url: {}, proxyies: {}, response: {}"
                     .format(full_url, proxy_dict, r.status_code))

    except requests.exceptions.RequestException as e:
        logging.exception("HTTP PUT request FAILED with {}"
                          .format(filename))
	time.sleep(1)
        r = requests.put(full_url,
                         data=open(filename, 'rb'),
                         headers=headers,
                         proxies=proxy_dict)
        sys.exit(1)

    return full_url, r


def curl(filename, path, bucket, config):

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

    headers = ' -H "Date: ' + date + '"' \
    ' -H "Authorization: AWS ' + config['vault']['access_key'] + ":" + signature + '"' \
    ' -H "Content-Type: ' + content_type + '"'\
    ' -H "Content-MD5: ' + file_checksum + '"'

    curl_command = 'curl -s -x ' + config['proxy']['https'] + ' -T ' +  filename + " " + full_url + headers
    logging.info("Curl Command: {}".format(curl_command))

    curl_out = os.popen(curl_command).read().replace('\n', '')
    logging.info("CURL_RETURN: {}".format(curl_out))

    return curl_out, full_url


def del_file(filename):
    if os.path.isfile(filename):
        try:
            os.remove(filename)
        except OSError as e:
            logging.error("Delete File Error: {} - {}".format(e.filename, e.strerror))


def main():
    logging.basicConfig(filename=LOG_FILE,
                        level=logging.DEBUG,
                        format='%(levelname)s\t%(asctime)s %(message)s')

    # Setup the command line argument parser.

    DESCRIPTION = ('vault upload')
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('bucket', type=str, help='a bucket name, eg. xxx-staging-log')
    parser.add_argument('catalog', type=str, help='a catalog name, eg. logstash')
    parser.add_argument('filename', type=str, nargs='+', help='upload files, eg. beats-2016-04-01.gz /data/output/*.log')
    args = parser.parse_args()

    # Get configration info
    config = get_configuration()

    # Start upload process
    for single_file in args.filename:
        filename_abs = os.path.abspath(single_file)
        filename_gpg_abs = execute_gpg_encryption(filename_abs, config)
        filename_gpg = os.path.basename(filename_gpg_abs)

        path = get_path(args.catalog, filename_gpg)
        curl_out, full_url = curl(filename_gpg_abs, path, args.bucket, config)
        del_file(filename_gpg_abs)

    logging.info('success upload file: {}'.format(args.filename))


if __name__ == '__main__':
    main()
