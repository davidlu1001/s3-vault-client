#!/usr/bin/env python
# encoding: utf-8

import os
import sys
import subprocess
import datetime
import yaml
import logging
import argparse
import hashlib
import hmac
import base64
import requests
import re
from pprint import pprint
from lxml import etree

try:
    import xml.etree.ElementTree as ET
except ImportError:
    # xml.etree.ElementTree was only added in python 2.5
    import elementtree.ElementTree as ET

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
        logging.info('Success to decrypt file: {}'.format(filename))
        return filename
    else:
        logging.error('file has unexpected suffix, please check.')
        return filename_gpg


def execute_list_request(bucket, config):
    """
    List file via HTTP GET requests.

    :return: requests.Response
    """

    date = get_date()
    message_temp = '\n'.join([date, '/{}'.format(bucket)])
    message = '\n\n\n'.join(['GET',message_temp])
    full_url_list = os.path.join(BASE_URL, bucket)
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
    }

    try:
        r = requests.get(full_url_list,
                         headers=headers,
                         stream=True)
        logging.info("HTTP GET request url: {}, response: {}"
                     .format(full_url_list, r.status_code))

    except requests.exceptions.RequestException as e:
        logging.exception("HTTP GET request FAILED with url: {}"
                          .format(full_url_list))
        sys.exit(1)

    return r


def execute_list_all_request(config):
    """
    List file via HTTP GET requests.

    :return: requests.Response
    """

    date = get_date()
    #message_temp = '\n'.join([date, '/{}'.format(bucket)])
    message_temp = '\n'.join([date, '/'])
    message = '\n\n\n'.join(['GET',message_temp])
    full_url_all = os.path.join(BASE_URL)
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
    }

    try:
        r = requests.get(full_url_all,
                         headers=headers,
                         stream=True)
        logging.info("HTTP GET request url: {}, response: {}"
                     .format(full_url_all, r.status_code))

    except requests.exceptions.RequestException as e:
        logging.exception("HTTP GET request FAILED all buckets")
        sys.exit(1)

    return r


def parseNodes(nodes):
    ## WARNING: Ignores text nodes from mixed xml/text.
    ## For instance <tag1>some text<tag2>other text</tag2></tag1>
    ## will be ignore "some text" node
    retval = []
    for node in nodes:
        retval_item = {}
        for child in node.getchildren():
            name = decode_from_s3(child.tag)
            if child.getchildren():
                retval_item[name] = parseNodes([child])
            else:
                found_text = node.findtext(".//%s" % child.tag)
                if found_text is not None:
                    retval_item[name] = decode_from_s3(found_text)
                else:
                    retval_item[name] = None
        retval.append(retval_item)
    return retval

def stripNameSpace(xml):
    """
    removeNameSpace(xml) -- remove top-level AWS namespace:

    <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">

    """
    r = re.compile('^(<?[^>]+?>\s?)(<\w+) xmlns=[\'"](http://[^\'"]+)[\'"](.*)', re.MULTILINE)
    if r.match(xml):
        xmlns = r.match(xml).groups()[2]
        xml = r.sub("\\1\\2\\4", xml)
    else:
        xmlns = None
    return xml, xmlns


def getTreeFromXml(xml):
    xml, xmlns = stripNameSpace(xml)
    try:
        tree = ET.fromstring(xml)
        if xmlns:
            tree.attrib['xmlns'] = xmlns
        return tree
    except Exception, e:
        logging.error("Error parsing xml: %s", e)
        raise


def getDictFromTree(tree):
    ret_dict = {}
    for child in tree.getchildren():
        if child.getchildren():
            ## Complex-type child. Recurse
            content = getDictFromTree(child)
        else:
            content = decode_from_s3(child.text) if child.text is not None else None
        child_tag = decode_from_s3(child.tag)
        if ret_dict.has_key(child_tag):
            if not type(ret_dict[child_tag]) == list:
                ret_dict[child_tag] = [ret_dict[child_tag]]
            ret_dict[child_tag].append(content or "")
        else:
            ret_dict[child_tag] = content or ""
    return ret_dict


def getTextFromXml(xml, xpath):
    tree = getTreeFromXml(xml)
    if tree.tag.endswith(xpath):
        return decode_from_s3(tree.text) if tree.text is not None else None
    else:
        result = tree.findtext(xpath)
        return decode_from_s3(result) if result is not None else None


def getRootTagName(xml):
    tree = getTreeFromXml(xml)
    return decode_from_s3(tree.tag) if tree.tag is not None else None


def xmlTextNode(tag_name, text):
    el = ET.Element(tag_name)
    el.text = decode_from_s3(text)
    return el


def appendXmlTextNode(tag_name, text, parent):
    """
    Creates a new <tag_name> Node and sets
    its content to 'text'. Then appends the
    created Node to 'parent' element if given.
    Returns the newly created Node.
    """
    el = xmlTextNode(tag_name, text)
    parent.append(el)
    return el


def decode_from_s3(string, errors = "replace"):
    """
    Convert S3 UTF-8 'string' to Unicode or raise an exception.
    """
    if type(string) == unicode:
        return string
    # Be quiet by default
    #debug("Decoding string from S3: %r" % string)
    try:
        return unicode(string, "UTF-8", errors)
    except UnicodeDecodeError:
        raise UnicodeDecodeError("Conversion to unicode failed: %r" % string)


def getListFromXml(xml, node):
    tree = getTreeFromXml(xml)
    nodes = tree.findall('.//%s' % (node))
    return parseNodes(nodes)


def list_all_buckets(config):

    resp = execute_list_all_request(config)

    # 01. use response.text
    # (decodes the response by default)

    #parser = etree.XMLParser(encoding='utf-8')
    #logging.info('RESP_RAW: {}'.format(resp.text))
    #root = etree.fromstring(resp.text.encode('utf-8'), parser=parser)
    #logging.info('ROOT: {}'.format(root))

    # 02. use response.content (recommended)
    # (undecoded so ElementTree can decode itself)
    root = etree.fromstring(resp.content)
    root_xml = etree.tostring(root,
                              encoding="UTF-8",
                              xml_declaration=True)

    bucket_lists = getListFromXml(root_xml, "Bucket")
    logging.info('Bucket list: {}'.format(bucket_lists))

    for bucket in bucket_lists:
        bucket_create_date = bucket['CreationDate'].replace('T', ' ').replace('.000Z', ' ')
        print("{}{}{}".format(bucket_create_date,
                             "\t",
                             bucket['Name']))


def list_bucket_info(bucket, config):

    truncated = True

    while truncated:
        resp = execute_list_request(bucket, config)
        root = etree.fromstring(resp.content)
        root_xml = etree.tostring(root,
                                encoding="UTF-8",
                                xml_declaration=True)
        current_list = get_contents(root_xml)
        current_prefixes = get_common_prefixes(root_xml)
        truncated = list_truncated(root_xml)
        logging.info("current list: {} current_prefix: {} truncated: {}".format(current_list, current_prefixes, truncated))

        if current_list:
            #key_output_dict_list = []
            for item in current_list:
                current_key =  item["Key"]
                current_key_mdate = item["LastModified"].replace('T', ' ').replace('.000Z', '')
                #logging.info('key: {} mdate: {}'.format(current_key, current_key_mdate))
                #key_output_dict_list.append({current_key:current_key_mdate})
                print('{}{}{}'.format(current_key_mdate, '\t', current_key))
            #pprint(key_output_dict_list)
        #current_keys = get_keys(current_list)
        #current_keys = current_list[-1]["Key"]


def list_truncated(root_xml):
    ## <IsTruncated> can either be "true" or "false" or be missing completely
    is_truncated = getTextFromXml(root_xml, ".//IsTruncated") or "false"
    return is_truncated.lower() != "false"

def get_contents(root_xml):
    return getListFromXml(root_xml, "Contents")

def get_common_prefixes(root_xml):
    return getListFromXml(root_xml, "CommonPrefixes")

def get_keys(root_xml):
    return getListFromXml(root_xml, "Key")


def main():
    logging.basicConfig(filename=LOG_FILE,
                        level=logging.INFO,
                        format='%(levelname)s\t%(asctime)s %(message)s')

    # Setup the command line argument parser.
    DESCRIPTION = ('vault list bucket')
    parser = argparse.ArgumentParser(description=DESCRIPTION)

    # tricks is: nargs='?' to accept "" or str input
    parser.add_argument('bucket', nargs='?', default='', type=str,
                        help='a bucket name, eg. msd-staging-log, list all buckets if "" or "/" provided')
    #parser.add_argument('catalog', type=str, help='a catalog name, eg. logstash')
    #parser.add_argument('ctime', type=str, help='a catalog name, eg. 2016/04/20')
    #parser.add_argument('filename', type=str, help='a upload file, eg. beats-2016-04-01.gz')

    args = parser.parse_args()
    config = get_configuration()

    if args.bucket == '' or args.bucket == '/':
        # List all buckets
        list_all_buckets(config)

    else:
        # List specified bucket
        list_bucket_info(args.bucket, config)


if __name__ == '__main__':
    main()

