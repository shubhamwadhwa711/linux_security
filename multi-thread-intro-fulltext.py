# -*- coding: utf-8 -*-
import requests
import lxml
from urllib.parse import urlparse
# import chardet
import pymysql.cursors
from pymysql import Connection
import validators
import warnings
import argparse
import configparser
import os
from logging import Logger
import re
import json
from pymysql import MySQLError
from ftplib import all_errors
from functools import partial

# import logging
from concurrent.futures import ThreadPoolExecutor, as_completed,ProcessPoolExecutor
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
from typing import Dict, Any, Optional
import copy
import asyncio
import aiohttp
import multiprocessing
import threading

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
from utils import (
    get_logger,
    timeit,
    current_state,
    percentage,
    check_http_broken_link,
    check_ftp_broken_link,
    check_url_against_domains,
    new_check_http_broken_link,
    write_file,
    HTTP_REQUEST_TIMEOUT,
    FTP_REQUEST_TIMEOUT,
    VALID_HTTP_STATUS_CODES,
    STATUS_CODES_FOR_FURTHER_CHECK,
    ColoredFormatter,
)


import json

# Load the configuration file
with open('config.json', 'r') as config_file:
    config_data = json.load(config_file)

# Access the lists
SKIP_CHECK_SITES = config_data['SKIP_CHECK_SITES']
DECOMPOSE_URLS = config_data['DECOMPOSE_URLS']
SITE_WITH_GET_METHOD = config_data['SITE_WITH_GET_METHOD']
FTP_DECOMPOSE_URLS = config_data['FTP_DECOMPOSE_URLS']



import logging

formatter = logging.Formatter(
    fmt='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def get_logger(name, log_file, level=logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    file = logging.FileHandler(log_file)        
    file.setFormatter(formatter)
    logger.addHandler(file)
    console = logging.StreamHandler()
    console.setFormatter(ColoredFormatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(console)
    return logger

@timeit
def do_update(
    connection: Connection,
    logger: Logger,
    id,
    introtext: Optional[str] = None,
    fulltext: Optional[str] = None,
):
    try:
        if introtext is None and fulltext is None:
            return False

        if introtext and fulltext:
            sql = "UPDATE xu5gc_content SET `introtext`=%s, `fulltext`=%s WHERE id=%s"
            args = (introtext, fulltext, id)
        elif introtext and fulltext is None:
            sql = "UPDATE xu5gc_content SET `introtext`=%s WHERE id=%s"
            args = (introtext, id)
        elif fulltext and introtext is None:
            sql = "UPDATE xu5gc_content SET `fulltext`=%s WHERE id=%s"
            args = (fulltext, id)
        else:
            return False

        with connection.cursor() as cursor:
            cursor.execute(sql, args)
        connection.commit()
        return True
    except MySQLError as e:
        logger.error(e)
        connection.rollback()
        raise e
    
def find_broken_urls(text):
    pattern = r"""\b(?:(?:(?:(?:https?|ftp?|sftp?):\/\/)|(?:www\.))|(?:ftp:)|(?<=href="|href=\'))[^\s<>]+(?:-\n){1}[^\s<>;]+\b[\/]?"""
    matches=re.findall(pattern,text)
    broken_links={}
    for m in matches:
        joined_url=re.sub(r'\n', '',m)
        broken_links[joined_url]=m
    return broken_links

def find_urls(text):
    pattern = r"""\b(?:(?:(?:(?:https?|ftp?|sftp?):\/\/)|(?:www\.))|(?:ftp:)|(?<=href="|href=\'))[^\s<>;]+\b[\/]?"""
    matches=re.findall(pattern,text)
    return matches


def process_broken_urls(html: str,logger:Logger,id:int,field:str):
    broken_links = find_broken_urls(html)
    updates=[]
    for correct_url, broken_url in broken_links.items():
        html = re.sub(broken_url, correct_url, html)
        logger.info(f'ID: {id} #COLUMN: {field} #URL: {broken_url} replaced with {correct_url}')
        updates.append(True)
    return html,updates


def decompose_known_urls(html:str,logger:Logger,id:int,field:str,updates:list):
    all_urls = find_urls(html)
    soup=BeautifulSoup(html,'html.parser')
    for url in all_urls:
        parsed_url = urlparse(url)
        if parsed_url.scheme in ['http','https']:
            domain = parsed_url.netloc
            domain=domain.lower()
            str_soup = str(soup)
            if domain in DECOMPOSE_URLS:
                a_tags = soup.find_all('a', attrs={'href': url})
                if len(a_tags)==0 and url in str_soup:
                    str_soup=str_soup.replace(url,"")
                    logger.info(f'ID: {id} #COLUMN: {field} #URL: {url} replaced with {"null"}')
                    updates.append(True)
                    pattern = r'((\n\s\n)|(\n{2}))'
                    str_soup=re.sub(pattern,'\n',str_soup)
                    soup=BeautifulSoup(str_soup,'html.parser')
                for tag in a_tags:
                    text=tag.text.strip()
                    updates.append(True)
                    if text and len(text)>0 and url not in text:
                        tag.replace_with(text)
                        logger.info(f'ID: {id} #COLUMN: {field} #URL: {url} replaced with {text}')
                    else:
                        tag.decompose()
                        logger.info(f'ID: {id} #COLUMN: {field} #URL: {url} replaced with {" "}')
        elif parsed_url.scheme in ['ftp']:
            domain = parsed_url.netloc
            domain=domain.lower()
            str_soup = str(soup)
            if domain in FTP_DECOMPOSE_URLS:
                a_tags = soup.find_all('a', attrs={'href': url})
                if len(a_tags)==0 and url in str_soup:
                    str_soup=str_soup.replace(url,"")
                    logger.info(f'ID: {id} #COLUMN: {field} #URL: {url} replaced with {"null"}')
                    updates.append(True)
                    pattern = r'((\n\s\n)|(\n{2}))'
                    str_soup=re.sub(pattern,'\n',str_soup)
                    soup=BeautifulSoup(str_soup,'html.parser')
                for tag in a_tags:
                    text=tag.text.strip()
                    updates.append(True)
                    if text and len(text)>0 and url not in text:
                        tag.replace_with(text)
                        logger.info(f'ID: {id} #COLUMN: {field} #URL: {url} replaced with {text}')
                    else:
                        tag.decompose()
                        logger.info(f'ID: {id} #COLUMN: {field} #URL: {url} replaced with {" "}')

    return str(soup),updates
    

def create_relative_urls(urls_obj: dict, base_url: str = None):
    urls_to_modify = list(urls_obj.keys())  # Create a copy of the keys as a list
    for url in urls_to_modify:
        original_url = copy.deepcopy(url)
        if not any(url.startswith(element) for element in ['http', 'https', 'www', 'ftp', 'ftps', "mailto:", "tel:", "#"]):
            url = f'{base_url}/{url[1:] if url.startswith("/") else url}'
            del urls_obj[original_url]
            urls_obj[url] = original_url  
    return urls_obj


def strip_trailing_in_anchor(url):
    if url.endswith(('.',':',';','>', '*', ',', '<pkg>','!')):
        url = url.rstrip('.;:,>*,!')
    # if url.endswith(('&gt;', '&gt')):
    url = url.replace('&gt', '')
    return url



def check_https_urls(url):
    if url.startswith("https://https://") or url.startswith("http://https://"):
       return True
    return False
        

def get_double_https(urls):
    obj=dict()
    for url in urls:
        original_url=copy.deepcopy(url)
        if url.startswith('https://https://'):
            url=url.replace('https://https://', 'https://')
        elif url.startswith('http://https://'):
            url=url.replace('http://https://',"http://") 
        elif url.startswith('www.'):
            url=f"https://{url}"
        url=strip_trailing_in_anchor(url)
        obj[url]=original_url
    return obj


async def new_do_http_request(urls,session,logger:Logger,id:int):
    tasks=[]
    for url in urls:
        task = asyncio.create_task(new_check_http_broken_link(url=url, session=session,logger=logger,id=id))
        tasks.append(task)
    result = await asyncio.gather(*tasks)
    for response in result:
        if not response['is_error'] or isinstance(response['status_code'],int):
            if response['status_code']< 400 or response['status_code'] in VALID_HTTP_STATUS_CODES:
                yield {'is_broken': False, 'status_code': response['status_code'], 'url': response['url']}
            else:
                yield {'is_broken': True, 'status_code': response['status_code'], 'url': response['url']}
        else:
            data=response['status_code']
            exception_type=str(data['type'])
            exception_message=data['message']
            if any(keyword in exception_type for keyword in ['ClientConnectorError','ClientConnectionError']):  
                if any(keyword in exception_message for keyword in ["Name or service not known","getaddrinfo failed","nodename nor servname","No address associated with hostname"]):
                    logger.error(f"#ID: {id} #URL {response['url']} Error: {exception_message}")
                    yield {'is_broken': True, 'status_code': 500, 'url': response['url']}
                else:
                    logger.warning(f"#ID: {id} #URL {response['url']} Error: {exception_message}") 
                    yield {'is_broken': False, 'status_code': 'ConnectionError', 'url': response['url']}

            elif any(keyword in exception_type for keyword in ['ClientSSLError','ClientConnectorSSLError']):
                logger.warning(f"#ID: {id} #URL {response['url']} Error: SSLError {exception_message}")
                yield {'is_broken': False, 'status_code': 'SSLError', 'url': response['url']}

            elif any(keyword in exception_type for keyword in ['TimeoutError']):
                logger.warning(f'#ID: {id} Error: Timeout {exception_message}')
                yield {'is_broken': False, 'status_code': 'Timeout', 'url': response['url']}
            else:
                logger.error(f'#ID: {id} #URL {url} Error: {exception_message}')
                yield {'is_broken': True, 'status_code': 500, 'url': response['url']}



def do_ftp_request(urls, logger: Logger, id: int):
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(check_ftp_broken_link, url=url, timeout=FTP_REQUEST_TIMEOUT): url for url in urls}
        for future in as_completed(futures):
            url = futures[future]
            try:
                response = future.result()
            except all_errors as e:
                logger.error(f'#ID: {id} #FTP_URL {url} #Error: {str(e)}')
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

def is_ftp_links(url):
    url = urlparse(url=url)
    if url.scheme in ['ftp', 'ftps']:
        return True
    return False

def check_ftp_urls( logger:Logger, id:int, updates:list,field:str, html: Optional[str] = None, urls:list=None):
    for_more_check_urls = set()
    soup=BeautifulSoup(html,'html.parser')
    for result in do_ftp_request(urls=urls, logger=logger, id=id):
        url = result.get('url')
        if not result.get('is_broken', False):
            # Link is still existing - no need to do anything
            updates.append(False)
            logger.info(f'Skipped ID: {id} #COLUMN: {field} #FTP_URL: {url if url else ("null")} #STATUS_CODE: {result.get("status_code")}')
            continue
        if result.get('status_code')==404:
            a_tags = soup.find_all('a', attrs={'href': url})
            str_soup=str(soup)
            if len(a_tags) == 0 and url in str_soup:
                str_soup=str_soup.replace(url," ")
                updates.append(True)
                pattern = r'((\n\s\n)|(\n{2}))'
                str_soup=re.sub(pattern,'\n',str_soup)
                soup=BeautifulSoup(str_soup,'html.parser')
            updates.append(True)
            for tag in a_tags:
                text = tag.text.strip()
                if text == url or len(text) == 0:
                    # If the link text is also a URL, we should probably remove the entire link and link text, as it will also create a problem
                    logger.info(f'ID: {id} #COLUMN: {field} #URL: {url if url else "(null)"} #STATUS_CODE: {result.get("status_code")} #TEXT: {"(null)" if len(text) == 0 else text} removed')
                    tag.decompose()
                else:
                    # Replace tag with tag text only
                    tag.replace_with(text)
                    logger.info(f'ID: {id} #COLUMN: {field} #URL: {url if url else "(null)"} #STATUS_CODE: {result.get("status_code")} - Replaced with #TEXT: {text}')
        else:
            for_more_check_urls.add(url)
    return str(soup), updates,for_more_check_urls

async def check_http_urls(logger:Logger, id:int,field:str,updates:list,base_url:str,html:Optional[str]=None, urls:list=None,for_more_check_urls:set=None):
    soup=BeautifulSoup(html,'html.parser')
    str_soup=str(soup)
    urls_obj=get_double_https(urls)
    urls = create_relative_urls(urls_obj,base_url)
    urls=list(urls_obj.keys())
    if len(urls)!=0:
        async with aiohttp.ClientSession() as session:
            async for result in new_do_http_request(urls=urls, session=session, logger=logger, id=id):            
                parsed_url = result.get('url')
                url=urls_obj.get(str(parsed_url),"")
                if not result.get('is_broken', False):
                    if check_https_urls(url):
                        a_tags = soup.find_all('a', attrs={'href': url})
                        if len(a_tags)==0 and url in str_soup:
                            str_soup=str_soup.replace(url,parsed_url) 
                            updates.append(True)
                            logger.info(f'ID: {id} #COLUMN: {field} #URL: {url} replaced with {parsed_url}')
                            soup=BeautifulSoup(str_soup,"html.parser")
                        for tag in a_tags:
                            tag['href']=parsed_url 
                            logger.info(f'ID: {id} #COLUMN: {field} #URL: {url} replaced with {parsed_url}') 
                        updates.append(True)
                        continue

                    updates.append(False)
                    if result.get('status_code') in VALID_HTTP_STATUS_CODES:
                        logger.warning(f'ID: {id} #COLUMN: {field} #URL: {parsed_url} #STATUS_CODE: {result.get("status_code")}')
                    else:
                        if result.get('status_code') in STATUS_CODES_FOR_FURTHER_CHECK:
                            logger.info(f'ID: {id} #COLUMN: {field} #URL: {url} added for more checking')
                            for_more_check_urls.add(url)
                        else:
                            logger.info(f'Skipped ID: {id} #COLUMN: {field} #URL: {parsed_url} #STATUS_CODE: {result.get("status_code")}')
                    continue
                
                
                if result.get('status_code')==404:
                    a_tags = soup.find_all('a', attrs={'href': url})
                    if len(a_tags) == 0 and url in str_soup:
                        str_soup=str_soup.replace(url,"")
                        logger.info(f'Skipped ID: {id} #COLUMN: {field} #URL: {url} #STATUS_CODE: {result.get("status_code")} #Replace with {"NULL"}')
                        updates.append(True)
                        pattern = r'((\n\s\n)|(\n{2}))'
                        str_soup=re.sub(pattern,'\n',str_soup)
                        soup=BeautifulSoup(str_soup,"html.parser")
                    updates.append(True)
                    for tag in a_tags:
                        text = tag.text.strip()
                        if text == url or len(text) == 0:
                            logger.info(f'ID: {id} #COLUMN: {field} #URL: {url if url else "(null)"} #STATUS_CODE: {result.get("status_code")} #TEXT: {"(null)" if len(text) == 0 else text} removed')
                            tag.decompose()
                        else:
                            tag.replace_with(text)
                            logger.info(f'ID: {id} #COLUMN: {field} #URL: {url if url else "(null)"} #STATUS_CODE: {result.get("status_code")} - Replaced with #TEXT: {text}')
                else:
                    for_more_check_urls.add(url)
                    logger.info(f'ID: {id} #COLUMN: {field} #URL: {url} added for more checking')
    return str(soup),updates,for_more_check_urls

def skip_check_sites(html,logger:Logger):
    all_urls = find_urls(html)
    remaining_urls=[]
    for url in all_urls:
        if url.startswith('#') or urlparse(url).netloc in SKIP_CHECK_SITES or urlparse(url).scheme in ["mailto", "tel"]:
            logger.info(f"{url} is skiped for checking:- present in SKIP_CHECK_SITES ")
            continue
        remaining_urls.append(url)
    return remaining_urls





def check_is_url_valid(html:str, logger:Logger, id:int,field:str,base_url:str,updates:list):
    all_urls=skip_check_sites(html,logger)
    ftp_urls = list(filter(lambda x: is_ftp_links(x), all_urls))
    http_urls = list(filter(lambda x: not is_ftp_links(x), all_urls))
    html,updates,for_more_check_urls = check_ftp_urls(html=html,urls= ftp_urls, logger=logger, id=id,field=field,updates=updates)
    html,updates,for_more_check_urls = asyncio.run(check_http_urls(html=html, urls=http_urls, logger=logger, id=id,field=field,updates=updates,base_url=base_url,for_more_check_urls=for_more_check_urls))
    return html,any(updates),for_more_check_urls

def process_html_text(logger: Logger, id: int, field: str, html: Optional[str] = None, base_url: str = None):
    try:
        for_more_check_urls = set()
        if html is None or len(html) == 0:
            return None, False, for_more_check_urls
        html,updates = process_broken_urls(html,logger=logger,id=id,field=field)
        html,updates = decompose_known_urls(html,logger=logger,id=id,field=field,updates=updates)
        html,updates,for_more_check_urls=check_is_url_valid(html,logger=logger,id=id,field=field,base_url=base_url,updates=updates)
        return html,updates,for_more_check_urls
    except Exception as e:
        logger.exception(e)
        raise e


def do_remove_url(record: Dict[str, Any], logger: Logger, base_url: str):
    id = record.get("id")
    introtext = record.get("introtext")
    introtext_json_data = introtext.strip().strip("\\")
    if introtext_json_data.startswith("{") and introtext_json_data.endswith("}"):
        logger.info(f"Skipped ID: {id} - introtext is a json data")
        adjusted_introtext, need_update_introtext, intro_timeout_urls = None, None, []
    else:
        logger.info(f"processing  {id} - introtext is not JSON, proceeding further to check HTML")
        adjusted_introtext, need_update_introtext, intro_timeout_urls = process_html_text(
            logger=logger, id=id, field="introtext", html=introtext, base_url=base_url
        )


    fulltext = record.get("fulltext")
    fulltext_json_data = fulltext.strip().strip("\\")
    if  fulltext_json_data.startswith("{") and fulltext_json_data.endswith("}"):
        logger.info(
        f"Skipped ID: {id} - fulltext a json data"
    )
        adjusted_fulltext, need_update_fulltext, full_timeout_urls = None, None, []
    else:
        logger.info(f"processing {id} - fulltext is not json proceeding further to check html")
        adjusted_fulltext, need_update_fulltext, full_timeout_urls = process_html_text(
            logger=logger, id=id, field="fulltext", html=fulltext, base_url=base_url
        )
    if adjusted_introtext is None and adjusted_fulltext is None:
        logger.info(
            f"Skipped ID: {id} - Not found any URLs in both introtext, fulltext fields"
        )
        return None, None, any([need_update_introtext, need_update_fulltext]), None

    return (
        adjusted_introtext if adjusted_introtext else introtext,
        adjusted_fulltext if adjusted_fulltext else fulltext,
        any([need_update_introtext, need_update_fulltext]),
        intro_timeout_urls.union(full_timeout_urls),
    )






def process_record(records, log_file, base_url, timeout_file, connection, commit):
    logger = get_logger(name=log_file, log_file=log_file)
    is_any_update_failed = False 
    counter=0 # Flag to track if any update fails
    total=len(records)
    for record in records:
        counter+=1
        try:
            logger.info(
                        f'{"*"*20} Processing ID: {record.get("id")} {"*"*20} ({counter}/{total} - {percentage(counter, total)})'
                    )
            introtext, fulltext, is_update, timeout_urls = do_remove_url(
                record=record, logger=logger, base_url=base_url
            )

            if timeout_urls and len(timeout_urls) > 0:
                write_file(
                    filename=timeout_file,
                    id=record.get("id"),
                    urls=timeout_urls,
                )

            if is_update is False:
                # Set the flag to True but continue processing other records
                is_any_update_failed = True
            else:
                if commit:
                    succeed = do_update(
                        connection=connection,
                        logger=logger,
                        id=record.get("id"),
                        introtext=introtext,
                        fulltext=fulltext,
                    )
                    if succeed:
                        logger.info(
                            f'ID: {record.get("id")} has been updated in the database'
                        )

            logger.info(f'Processing ID: {record.get("id")} completed')
        except KeyboardInterrupt as e:
            current_id = record.get("id")
            raise e
        except Exception as e:
            continue

    latest = records[-1]
    current_id = latest.get("id")
    return current_id, is_any_update_failed

    


def get_data_chunk(start, chunk_size,connection):
    offset = start  
    limit = chunk_size  
    sql="SELECT c.id, c.introtext, c.fulltext FROM xu5gc_content AS c LEFT JOIN xu5gc_categories cat ON cat.id = c.catid WHERE c.state = 1 AND cat.published = 1 ORDER BY c.id  LIMIT %s OFFSET %s"
    with connection.cursor() as cursor:
        cursor.execute(sql, (limit, offset))
        results = cursor.fetchall()
        return results




def main(commit: bool = False, id: Optional[int] = 0):
    config = configparser.ConfigParser(interpolation=None)
    config.read(os.path.join(os.path.dirname(__file__), "config.ini"))

    log_file = config.get("script-01", "log_file")
    store_state_file = config.get("script-01", "store_state_file")
    timeout_file = config.get("script-01", "timeout_file")

    limit: int = config["script-01"].getint("limit")
    base_url: str = config.get("script-01", "base_url")

    logger: Logger = get_logger(name=log_file, log_file=log_file)

    try:
        # Connect to the database
        connection: Connection = pymysql.connect(
            host=config.get("mysql", "host"),
            port=int(config.get("mysql", "port")),
            user=config.get("mysql", "user"),
            password=config.get("mysql", "password"),
            database=config.get("mysql", "database"),
            cursorclass=pymysql.cursors.DictCursor,
        )
    except MySQLError as e:
        logger.error(e)
        raise e

    with connection.cursor() as cursor:
        sql = "SELECT count(c.id) as total FROM xu5gc_content c LEFT JOIN xu5gc_categories cat ON cat.id = c.catid WHERE c.state = 1 AND cat.published = 1"
        cursor.execute(sql)
        result = cursor.fetchone()

    total = result.get("total") if id == 0 else 1
    if commit and id == 0:
        # read current running state from file if commit is True
        current_id, counter = current_state(store_state_file, mode="r")
    else:
        current_id = 0
        counter = 0
    
    chunk_size=total//multiprocessing.cpu_count()
    data_chunks=[]
    all_data=False
    

    while True:
        try:
            if current_id > 0:
                sql = "SELECT c.id, c.introtext, c.fulltext FROM xu5gc_content AS c LEFT JOIN xu5gc_categories cat ON cat.id = c.catid WHERE c.state = 1 AND cat.published = 1 AND c.id < %s ORDER BY  c.id DESC LIMIT %s"
                args = (current_id, limit)
                with connection.cursor() as cursor:
                    cursor.execute(sql, args)
                    result = cursor.fetchall()

            elif id > 0:
                sql = "SELECT c.id, c.introtext, c.fulltext FROM xu5gc_content AS c WHERE id =%s"
                args = id
                with connection.cursor() as cursor:
                    cursor.execute(sql, args)
                    result = cursor.fetchall()
            else:
                all_data=True
                for start in range(0, total, chunk_size):
                    data_chunk = get_data_chunk(start, chunk_size,connection)
                    data_chunks.append(data_chunk)
                chunk_completion = {i: False for i in range(len(data_chunks))}
                nested_log_files = [f"process_{i}.log"for i in range(len(data_chunks))]
                with ThreadPoolExecutor() as executor:
                    futures = executor.map(process_record, data_chunks, nested_log_files, [base_url] * len(data_chunks), [timeout_file] * len(data_chunks), [connection] * len(data_chunks), [commit] * len(data_chunks))

                    # futures = [executor.submit(process_record, record, base_url, timeout_file, connection, commit, log_file) for record, log_file in zip(data_chunks, nested_log_files)]
                # for future in as_completed(futures):
                for future in futures:
                    i, is_any_update_failed = future

                    if commit and id == 0:
                        current_state(
                            store_state_file, id=i, counter=counter, mode="w"
                        )
                    for idx,chunk in enumerate(data_chunks):
                        if chunk[-1]['id']==i:
                            chunk_completion[idx] = True   
                    if is_any_update_failed:
                        pass
                        # logger.info(f'{"="*20}  chunk {i} has no upddates {"="*20}')

                for i, completed in chunk_completion.items():
                    if completed:
                        logger.info(f'{"="*20}  chunk {i} records have been processed {"="*20}')
                    else:
                        print(f"Chunk {i} is still processing")

                with open(log_file, "w") as consolidated_log:
                    for i in nested_log_files:
                        with open(i, "r") as individual_log:
                            consolidated_log.write(individual_log.read())   
                break    

 

                # with multiprocessing.Pool() as p:
                #     p.starmap(process_record, [(records, logger, base_url, timeout_file, connection, commit) for records in data_chunks])
            if not all_data:
                if len(result) == 0:
                    logger.info(f'{"="*20} All records have been processed {"="*20}')
                    break

                for record in result:
                    counter += 1
                    try:
                        logger.info(
                            f'{"*"*20} Processing ID: {record.get("id")} {"*"*20} ({counter}/{total} - {percentage(counter, total)})'
                        )
                        introtext, fulltext, is_update, timeout_urls = do_remove_url(
                            record=record, logger=logger, base_url=base_url
                        )
                        if timeout_urls and len(timeout_urls) > 0:
                            write_file(
                                filename=timeout_file,
                                id=record.get("id"),
                                urls=timeout_urls,
                            )

                        if is_update is False:
                            continue

                        if commit:
                            succeed = do_update(
                                connection=connection,
                                logger=logger,
                                id=record.get("id"),
                                introtext=introtext,
                                fulltext=fulltext,
                            )
                            if succeed:
                                logger.info(
                                    f'ID: {record.get("id")} has been updated in database'
                                )

                        logger.info(f'Processing ID: {record.get("id")} completed')
                    except KeyboardInterrupt as e:
                        current_id = record.get("id")
                        raise e
                    except Exception as e:
                        logger.error(e)
                        continue
                if id > 0:
                    logger.info(f'{"="*20} All records have been processed {"="*20}')
                    break

                latest = result[-1]
                current_id = latest.get("id")

                if commit and id == 0:
                    # write current running state to file if commit is True
                    current_state(
                        store_state_file, id=current_id, counter=counter, mode="w"
                    )
        except KeyboardInterrupt:
            if commit and id == 0:
                current_state(
                    store_state_file, id=current_id, counter=counter, mode="w"
                )
            break

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", action="store_true", help="Update the database")
    parser.add_argument("--id", default=0, type=int, help="Check for specific ID")

    args = parser.parse_args()
    is_commit = args.commit
    specific_id = args.id

    main(commit=is_commit, id=specific_id)