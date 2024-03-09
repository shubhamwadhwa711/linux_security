# -*- coding: utf-8 -*-
import requests
import lxml
import pymysql.cursors
import validators
import json
import configparser
import argparse
import os
from pymysql import Connection
from json.decoder import JSONDecodeError
from pymysql import MySQLError
from ftplib import all_errors
from logging import Logger
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
from typing import Dict, Any, Optional, List
import warnings
from urllib.parse import urlparse
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

from utils import (
    get_logger,
    timeit,
    current_state,
    percentage,
    check_http_broken_link,
    check_ftp_broken_link,
    write_file,
    HTTP_REQUEST_TIMEOUT,
    FTP_REQUEST_TIMEOUT,
    VALID_HTTP_STATUS_CODES,
    STATUS_CODES_FOR_FURTHER_CHECK
)
with open('config.json', 'r') as config_file:
    config_data = json.load(config_file)
DECOMPOSE_URLS = config_data['DECOMPOSE_URLS']
FTP_DECOMPOSE_URLS = config_data['FTP_DECOMPOSE_URLS']
PREDETERMINE_LIST=config_data['PREDETERMINE_LIST']

@timeit
def do_update(connection: Connection, id: int, urls: Optional[Any] = None, fulltext: Optional[str] = None, logger: Logger = None):
    try:
        with connection.cursor() as cursor:
            sql = 'UPDATE xu5gc_content SET `urls`=%s, `fulltext`=%s WHERE id=%s'
            args = (json.dumps(urls), fulltext, id)
            cursor.execute(sql, args)
        connection.commit()
        return True
    except MySQLError as e:
        logger.error(json.dumps({"Error":str(e)}))
        connection.rollback()
        raise e


def decompose_url(url):
    parsed_url = urlparse(url)
    if parsed_url.scheme in ['http','https']:
        domain = parsed_url.netloc
        domain=domain.lower()
        if domain in DECOMPOSE_URLS:
            return True
    elif parsed_url.scheme in ['ftp']:
            domain = parsed_url.netloc
            domain=domain.lower()
            if domain in FTP_DECOMPOSE_URLS:
                return True
    elif any(i in url for i in PREDETERMINE_LIST):
        return  True
    return False


# @timeit
def do_http_request(urls: List[str], logger: Logger, id: int):
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(check_http_broken_link, url=url, logger=logger, id=id, timeout=HTTP_REQUEST_TIMEOUT): url for url in urls}
        for future in as_completed(futures):
            url = futures[future]
            try:
                response = future.result()
            except requests.Timeout as e:
                logger.warning(json.dumps({'ID': id, "URL": url, "Error": f"Timeout {str(e)}"}))
                yield {'is_broken': False, 'status_code': 'Timeout', 'url': url}
            except requests.exceptions.SSLError as e:
                logger.warning(json.dumps({'ID': id, "URL": url, "Error": f"SSL ERROR {str(e)}"}))
                yield {'is_broken': False, 'status_code': 'SSLError', 'url': url}
            except requests.exceptions.ConnectionError as e:
                if ("[Errno 11001] getaddrinfo failed" in str(e) or     # Windows
                    "[Errno -2] Name or service not known" in str(e) or # Linux
                    "[Errno 8] nodename nor servname" in str(e) or
                    "[Errno -5] No address associated with hostname" in str(e)):      # OS X
                    logger.warning(json.dumps({'ID': id, "URL": url, "Error": str(e)}))
                    yield {'is_broken': True, 'status_code': 500, 'url': url}
                else:
                    logger.warning(json.dumps({'ID': id, "URL": url, "Error": str(e)}))
                    yield {'is_broken': False, 'status_code': 'ConnectionError', 'url': url}
            except Exception as e:
                logger.error(json.dumps({'ID': id, "URL": url, "Error": str(e)}))
                yield {'is_broken': True, 'status_code': 500, 'url': url}
            else:
                if response['status_code'] < 400 or response['status_code'] in VALID_HTTP_STATUS_CODES:
                    yield {'is_broken': False, 'status_code':response['status_code'], 'url': url}
                else:
                    yield {'is_broken': True, 'status_code': response['status_code'], 'url': url}

def do_ftp_request(urls: List[str], logger: Logger):
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(check_ftp_broken_link, url=url, timeout=FTP_REQUEST_TIMEOUT): url for url in urls}
        for future in as_completed(futures):
            url = futures[future]
            try:
                response = future.result()
            except all_errors as e:
                logger.error(json.dumps({"Error":str(e)}))
                try:
                    errorcode = int(str(e).split(None, 1)[0])
                except:
                    errorcode = str(e)
                yield {'is_broken': True, 'status_code': errorcode, 'url': url}
            else:
                if response:
                    yield {'is_broken': False, 'status_code': 200, 'url': url}
                else:
                    yield {'is_broken': True, 'status_code': 500, 'url': url}


# @timeit
def append_text(html: Optional[str] = None, text: str = None):
    if html is None or len(html) == 0:
        return None

    soup = BeautifulSoup(html, 'lxml')
    p_tag = soup.new_tag("p")
    b_tag = soup.new_tag("b")
    b_tag.string = f"The link for this article located at {text.strip()} is no longer available."
    p_tag.append(b_tag)

    if soup.find('body'):
        soup.body.append(p_tag)
    else:
        soup.append(p_tag)

    return str(soup)

def is_broken_url(id: int, url: str, logger: Logger, timeout_file: str):
    is_valid_url = validators.url(url)
    if not is_valid_url:
        logger.info(json.dumps({'ID': id ,"URL": url ,"STATUS_CODE": "INVALID URL"}))
        return True
    if url.startswith('ftp'):
        for result in do_ftp_request(urls=[url], logger=logger):
            is_broken = result.get('is_broken', False)
            if is_broken is False :
                logger.info(json.dumps({'Skipped ID': id, "URL": url ,"STATUS_CODE": result.get("status_code")}))
            else:
                logger.info(json.dumps({'ID': id, "URL": url ,"STATUS_CODE": f"{result.get('status_code')}removed"}))
            return is_broken
    else:
        for result in do_http_request(urls=[url], logger=logger, id=id):
            is_broken = result.get('is_broken', False)
            if is_broken is False :
                if result.get('status_code') in VALID_HTTP_STATUS_CODES:
                    logger.warning(json.dumps({'ID': id, "URL": url ,"STATUS_CODE": result.get("status_code")}))
                else:
                    if result.get('status_code') in STATUS_CODES_FOR_FURTHER_CHECK:
                        logger.info(json.dumps({'ID': id, "URL": url ,"Action": "Added for more checking"}))
                        write_file(filename=timeout_file, id=id, urls=[url])
                    else:
                        logger.info(json.dumps({'Skipped ID': id, "URL": url ,"STATUS_CODE": result.get("status_code")}))
            else:
                logger.info(json.dumps({'ID': id, "URL": url ,"STATUS_CODE": f"{result.get('status_code')} removed "}))
            return is_broken
    
def main(commit: bool = False, id: Optional[int] = 0):
    config = configparser.RawConfigParser()
    config.read(os.path.join(os.path.dirname(__file__), 'config.ini'))

    log_file = config.get('script-02', 'log_file')
    store_state_file = config.get('script-02', 'store_state_file')
    limit: int = config['script-02'].getint('limit')
    timeout_file = config.get('script-02', 'timeout_file')

    logger = get_logger(name=log_file, log_file=log_file)

    try:
        # Connect to the database
        connection: Connection = pymysql.connect(
            host=config.get('mysql', 'host'),
            user=config.get('mysql', 'user'),
            password=config.get('mysql', 'password'),
            database=config.get('mysql', 'database'),
            cursorclass=pymysql.cursors.DictCursor
        )
    except MySQLError as e:
        logger.error(json.dumps({"Error":str(e)}))
        raise e
    
    with connection.cursor() as cursor:
        sql = "SELECT count(co.id) as total FROM xu5gc_content AS co left join xu5gc_categories AS ca ON co.catid=ca.id WHERE co.state=1 and ca.published = 1 and trim(coalesce(co.urls, '')) <>''"
        cursor.execute(sql)
        result =  cursor.fetchone()

    total = result.get('total') if id == 0 else 1

    if commit and id == 0:
        # read current running state from file if commit is True
        current_id, counter = current_state(store_state_file, mode='r')
    else:
        current_id = 0
        counter = 0

    while True:
        try:
            if current_id > 0:
                sql = "SELECT co.id, co.fulltext, co.urls FROM xu5gc_content AS co LEFT JOIN xu5gc_categories AS ca ON co.catid=ca.id WHERE co.state=1 and ca.published = 1 AND co.id < %s AND trim(coalesce(co.urls, '')) <>'' ORDER BY co.id DESC LIMIT %s"
                args = (current_id, limit)
            elif id > 0:
                sql = 'SELECT co.id, co.urls, co.fulltext FROM xu5gc_content AS co LEFT JOIN xu5gc_categories AS ca ON co.catid=ca.id WHERE co.state=1 and ca.published = 1 AND co.id =%s'
                args = (id)
            else:
                sql = "SELECT co.id, co.fulltext, co.urls FROM xu5gc_content AS co LEFT JOIN xu5gc_categories as ca ON co.catid=ca.id WHERE co.state=1 AND ca.published = 1 AND trim(coalesce(co.urls, '')) <>'' ORDER BY co.id DESC LIMIT %s"
                args = (limit)

            with connection.cursor() as cursor:
                cursor.execute(sql, args)
                result =  cursor.fetchall()
            
            if len(result) == 0:
                logger.info(json.dumps({"Action":"All records have been processed"}))
                break

            for record in result:
                counter += 1
                try:
                    logger.info(json.dumps({"Processing ID": record.get("id"),"processed_records":f"({counter}/{total}" ,"percentage": percentage(counter, total)}))
                    raw_urls = record.get('urls')
                    if raw_urls is None or len(raw_urls) == 0:
                        logger.info(json.dumps({'Skipped ID': record.get("id") ,"urls": raw_urls,"Action" : "URLs is empty"}))
                        continue

                    try:
                        urls = json.loads(raw_urls, strict=False)
                    except JSONDecodeError as e:
                        logger.error(json.dumps({'Skipped ID': record.get("id"), "url": raw_urls,"JSON Error": str(e)}))
                        continue

                    urla = urls.get('urla')
                    urlatext = urls.get('urlatext')
                    if urla is None or isinstance(urla, bool) or len(urla) == 0:
                        logger.info(json.dumps({'Skipped ID': record.get("id") ,"urls": urls,"Action" : "URLs is empty"}))
                        continue
                    decompose_url_result=decompose_url(urla)
                    if not decompose_url_result:
                        is_broken = is_broken_url(id=record.get("id"), url=urla, logger=logger, timeout_file=timeout_file)
                        if is_broken is False:
                            continue
                    
                    fulltext = record.get('fulltext')
                    updated_fulltext = append_text(html=fulltext, text=urlatext)
                    updated_urls = urls.copy()
                    updated_urls['urla'] = ""
                    logger.info(json.dumps({"ID": record.get("id"), "old_urls": urls, "new urls" :updated_urls}))

                    if commit:
                        succeed = do_update(
                            connection=connection,
                            id=record.get("id"),
                            urls=updated_urls,
                            fulltext=updated_fulltext,
                            logger=logger
                        )
                        if succeed:
                            logger.info(json.dumps({'ID': record.get("id"),"Action":"updated in database"}))
                    logger.info(json.dumps({"Processed - ID": record.get("id"),"Action":"Processing completed"}))
                except KeyboardInterrupt as e:
                    current_id = record.get("id")
                    raise e
                except Exception as e:
                    logger.error(json.dumps({"Error":str(e)}))
                    continue
            
            if id > 0:
                logger.info(json.dumps({"Action":"All records have been processed"}))
                break
        
            latest = result[-1]
            current_id = latest.get('id')
            if commit and id == 0:
                current_state(store_state_file, id=current_id, counter=counter, mode='w')
        except KeyboardInterrupt as e:
            if commit and id == 0:
                current_state(store_state_file, id=current_id, counter=counter, mode='w')
            break

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", action="store_true", help="Update the database")
    parser.add_argument("--id", default=0, type=int, help="Check for specific ID")

    args = parser.parse_args()
    is_commit = args.commit
    specific_id = args.id

    main(commit=is_commit, id=specific_id)
