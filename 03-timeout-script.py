# -*- coding: utf-8 -*-
from concurrent.futures import ThreadPoolExecutor, as_completed
from json import JSONDecodeError
import json
import requests
import html as ht
# import lxml
# import chardet
import pymysql.cursors
import os
import sys
from pymysql import Connection
import validators
from ftplib import all_errors
import warnings
import argparse
import configparser
from logging import Logger
from pymysql import MySQLError
from typing import Dict, Any, Optional, List
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
# from typing import Dict, Any, Optional
import re
import json
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

from utils import (
    get_logger,
    timeit,
    current_state,
    percentage,
    check_http_broken_link,
    check_ftp_broken_link,
    write_file,
    read_file,
    HTTP_REQUEST_TIMEOUT,
    FTP_REQUEST_TIMEOUT,
    VALID_HTTP_STATUS_CODES,
    STATUS_CODES_FOR_FURTHER_CHECK,
)


# Load the configuration file
with open('config.json', 'r') as config_file:
    config_data = json.load(config_file)

# Access the lists
SKIP_CHECK_SITES = config_data['SKIP_CHECK_SITES']

def find_text_links(text):
    # Regular expression pattern to match HTTP and HTTPS links not within anchor tags
    # pattern = r'(?<!href=")(?P<url>(?:http|https)://[^\s<>"]+|www\.[^\s<>"]+)'
    pattern = r'(?<!href="|href=\')(http[s]?:\/\/(?:[^\s<>"]+|www\.[^\s<>"]+))(?![^<]*>|[^<>]*<\/a>)'

def do_http_request(urls, logger: Logger, id: int, timeout = HTTP_REQUEST_TIMEOUT):
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(check_http_broken_link, url=url, logger=logger, id=id, timeout=timeout): url for url in urls}
        for future in as_completed(futures):
            url = futures[future]
            try:
                response = future.result()
            except requests.Timeout as e:
                logger.error(json.dumps({'ID': id, 'URL': url ,'Error':f" Timeout {str(e)}"}))
                yield {'is_broken': True, 'status_code': 'Timeout', 'url': url}
            except requests.exceptions.SSLError as e:
                logger.error(json.dumps({'ID': id, 'URL': url ,'Error':f" SSL {str(e)}"}))
                yield {'is_broken': True, 'status_code': 'SSLError', 'url': url}
            except Exception as e:
                logger.error(json.dumps({'ID': id, 'URL': url ,'Error':str(e)}))
                yield {'is_broken': True, 'status_code': 500, 'url': url}
            else:
                if response['status_code'] < 400 or response['status_code'] in VALID_HTTP_STATUS_CODES:
                    yield {'is_broken': False, 'status_code': response['status_code'], 'url': url}
                else:
                    yield {'is_broken': True, 'status_code': response['status_code'], 'url': url}


def do_ftp_request(urls, logger: Logger, id: int):
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(check_ftp_broken_link, url=url,logger=logger, timeout=FTP_REQUEST_TIMEOUT): url for url in urls}
        for future in as_completed(futures):
            url = futures[future]
            try:
                response = future.result()
            except all_errors as e:
                logger.error(json.dumps({'ID': id,'FTP_URL': url,'Error': str(e)}))
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

def find_a_tag_in_html(logger: Logger, field: str, html: Optional[str] = None, urls: Optional[List[str]] = None):
    try:
        if html is None or len(html) == 0:
            return None, False

        soup = BeautifulSoup(html, 'html.parser')
        str_soup=str(soup)
        updates = []
        for url in urls:
            decode_url=ht.unescape(url)
            a_tags = soup.find_all('a', attrs={'href': decode_url})
            for tag in a_tags:
                text = tag.text.strip()
                updates.append(True)
                if text and len(text) > 0 and url not in text:
                    tag.replace_with(text)
                    logger.info(json.dumps({"COLUMN":field, "URL": url , "Action": f"Replaced with  {text} removed"}))
                else:
                    tag.decompose()
                    logger.info(json.dumps({"COLUMN":field, "URL": url , "Action": "Replaced with  (empty) removed"}))
            if len(a_tags) == 0 and url in str_soup:
                pattern = re.escape(url) + r'(\r\n|\n)'
                if re.search(pattern, str_soup):
                    str_soup = re.sub(pattern, '', str_soup)
                else:
                    str_soup = str_soup.replace(url, '')
                logger.info(json.dumps({"COLUMN":field, "URL": url , "Action": "Replaced with  (empty) removed"}))
                updates.append(True)
                soup = BeautifulSoup(str_soup, 'html.parser')
        return soup, any(updates)
    except Exception as e:
        logger.error(json.dumps({"Error":str(e)}))
        raise e
    
def get_database_record(connection: Connection, logger: Logger, id: int, is_urla: bool = False):
    try:
        if is_urla:
            sql = 'SELECT urls, `fulltext` FROM xu5gc_content WHERE id=%s'
        else:
            sql = 'SELECT `introtext`, `fulltext` FROM xu5gc_content WHERE id=%s'

        with connection.cursor() as cursor:
            cursor.execute(sql, (id))
            result =  cursor.fetchone()
        return result
    except MySQLError as e:
        logger.error(json.dumps({"ERROR":str(e)}))
        raise e

def do_update_intro_fulltext(record, connection: Connection, logger: Logger, id: int, urls: List[str], commit: bool = False):
    try:
        cmd = []
        args = set()
        for key, value in record.items():
            html, update = find_a_tag_in_html(logger=logger, field=key, html=value, urls=urls)
            if update is False:
                continue

            cmd.append(f'`{key}`=%s')
            args.add(html)

        if len(cmd) == 0 or len(args) == 0:
            return False
        
        if commit:
            str_ = ', '.join(c for c in cmd)
            sql = f'UPDATE xu5gc_content SET {str_} WHERE id={id}'
            with connection.cursor() as cursor:
                cursor.execute(sql, tuple(args))
            connection.commit()

            logger.info(json.dumps({"ID":id,"Action":"update in database"}))
        return True
    except MySQLError as e:
        connection.rollback()
        raise e
    except Exception as e:
        raise e

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

def do_update_urla(record, connection: Connection, logger: Logger, id: int, commit: bool = False):
    try:
        raw_urls = record.get('urls')
        if raw_urls is None or len(raw_urls) == 0:
            return False
    
        urls = json.loads(raw_urls, strict=False)
        urla = urls.get('urla')
        urlatext = urls.get('urlatext')
        if urla is None or isinstance(urla, bool) or len(urla) == 0:
            return False
        
        fulltext = record.get('fulltext')
        replaced_fulltext = append_text(html=fulltext, text=urlatext)
    
        updated_urls = urls.copy()
        updated_urls['urla'] = ""
        logger.info(json.dumps({"ID":id,"old_urls":urls,"updated_urls":updated_urls,"Action":"change old to new"}))
        if commit:
            with connection.cursor() as cursor:
                sql = 'UPDATE xu5gc_content SET `urls`=%s, `fulltext`=%s WHERE id=%s'
                args = (json.dumps(updated_urls), replaced_fulltext, id)
                cursor.execute(sql, args)
            connection.commit()
            logger.info(json.dumps({"ID" :id,"Action":"update database"}))
        return True
    except JSONDecodeError as e:
        logger.warning(json.dumps({"id":id,"Error":str(e)}))
        return False
    except MySQLError as e:
        logger.error(json.dumps({"id":id,"Error":str(e)}))
        connection.rollback()
        raise e
    except Exception as e:
        logger.error(json.dumps({"id":id,"Error":str(e)}))
        raise e

def do_update(connection: Connection, logger: Logger, id: int, urls: List[str], is_urla: bool = False, commit: bool = False):
    try:
        if len(urls) == 0:
            return False

        record = get_database_record(connection=connection, logger=logger, id=id, is_urla=is_urla)
        if record is None:
            logger.info(json.dumps({"ID": id,"Action":"does not exist"}))
            return False
        
        if is_urla:
            succeed =  do_update_urla(record=record, connection=connection, logger=logger, id=id, commit=commit)
        else:
            succeed = do_update_intro_fulltext(record=record, connection=connection, logger=logger, id=id, urls=urls, commit=commit)
        return succeed
    except MySQLError as e:
        logger.error(json.dumps({"id":id,"Error":str(e)}))
        connection.rollback()
    except Exception as e:
        logger.error(json.dumps({"id":id,"Error":str(e)}))
        raise e

def main(commit, file_path, is_urla: bool = False, timeout: int = 15):
    config = configparser.ConfigParser(interpolation=None)
    config.read(os.path.join(os.path.dirname(__file__), 'config.ini'))

    log_file = config.get('script-03', 'log_file')

    logger: Logger = get_logger(
        name=log_file,
        log_file=log_file
    )

    try:
        # Connect to the database
        connection: Connection = pymysql.connect(
            host=config.get('mysql', 'host'),
            port=int(config.get('mysql', 'port')),
            user=config.get('mysql', 'user'),
            password=config.get('mysql', 'password'),
            database=config.get('mysql', 'database'),
            cursorclass=pymysql.cursors.DictCursor
        )
    except MySQLError as e:
        logger.error(json.dumps({"error":str(e)}))
        raise e
    
    try:
        data = read_file(file_path)
        if not data:
            logger.info(json.dumps({"Action":"There is no URLs to check"}))

        for id, urls in data.items():
            logger.info(json.dumps({"Action":f"Processing ID: {id}"}))
            remain_urls = [*urls]
            replace_urls = []
            urls=[url.replace("http://https://","http://").replace("https://https://","https://") if url.startswith("http://https://") or url.startswith("https://https://") else url for url in urls]
            http_urls=list(filter(lambda x: not x.startswith('ftp://'),[f"https://{url}" if url.startswith('www.') else url  for url in urls]))
            ftp_urls = list(filter(lambda x: x.startswith('ftp://'), urls))
            new_http_urls = {(f"https://linuxsecurity.com/{url}" if not url.startswith(("https://", "http://")) else url): url for url in http_urls}
            for result in do_http_request(urls=new_http_urls.keys(), logger=logger, id=id, timeout=timeout):
                parsed_url = result.get('url')
                url=new_http_urls[parsed_url]
                if not result.get('is_broken', False):
                    logger.info(json.dumps({'Skipped ID': id, "URL": parsed_url, "STATUS_CODE": result.get("status_code")}))
                    if commit:
                         remain_urls = [href for href in remain_urls if href != url]

                    continue
                
                replace_urls.append(url)

            for result in do_ftp_request(urls=ftp_urls, logger=logger, id=id):
                url = result.get('url')
                if not result.get('is_broken', False):
                    logger.info(json.dumps({'Skipped ID': id, "URL": parsed_url, "STATUS_CODE": result.get("status_code")}))
                    if commit:
                        remain_urls = [href for href in remain_urls if href != url]
                    continue
                
                replace_urls.append(url)


            do_update(
                connection=connection,
                logger=logger,
                id=id,
                urls=replace_urls,
                is_urla=is_urla,
                commit=commit
            )

            if commit is False:
                write_file(filename=file_path, id=id, urls=remain_urls)
            else:
                write_file(filename=file_path, id=id, urls=None)

            logger.info(json.dumps({"ID":id ,"Action":f"Processing ID: {id} completed"}))
    except Exception as e:
        raise e

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", action="store_true", help="Update the database")
    parser.add_argument("--file", type=str, help="File for more check")
    parser.add_argument("--urla", action="store_true", help="Check URLa field")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout")

    args = parser.parse_args()
    is_commit = args.commit
    file_path = args.file
    is_urla = args.urla
    timeout = args.timeout

    if file_path is None:
        print('Please input file path')
        sys.exit(0)
    if not os.path.exists(file_path):
        print(f'File {file_path} does not exist')
        sys.exit(0)
    
    main(commit=is_commit, file_path=file_path, is_urla=is_urla, timeout=timeout)
