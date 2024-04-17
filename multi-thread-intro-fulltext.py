# -*- coding: utf-8 -*-
import requests
import lxml
from urllib.parse import urlparse
# import chardet
import pymysql.cursors
from pymysql import Connection
import validators
import warnings
import html as ht
import argparse
import configparser
import os
from logging import Logger
import re
import json
from pymysql import MySQLError
from ftplib import all_errors
from functools import partial
import csv
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
    write_img_urls,
    write_redirect_urls,
    concatenate_log_files,
    concatenate_img_csv_files,
    concatenate_timeout_files,
    concatenate_redirected_urls_file,
    write_generic_modified_url_file,
    concatenate_generic_modfiled_url_file
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
PREDETERMINE_LIST=config_data['PREDETERMINE_LIST']



import logging

formatter = logging.Formatter(
    fmt='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "time": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage()
        }
        return json.dumps(log_record)

def get_logger(name, log_file,log_level, level=logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    file = logging.FileHandler(log_file)  
    json_formatter = JsonFormatter()      
    file.setFormatter(json_formatter)
    logger.addHandler(file)
    if not log_level:
        console = logging.StreamHandler()
        console.setFormatter(ColoredFormatter("%(asctime)s - %(levelname)s - %(message)s"))
        logger.addHandler(console)
    return logger

@timeit
def do_update(
    connection: Connection,
    logger: Logger,
    id,
    table_prefix,
    introtext: Optional[str] = None,
    fulltext: Optional[str] = None,
    
):
    try:
        if introtext is None and fulltext is None:
            return False

        if introtext and fulltext:
            sql = f"UPDATE {table_prefix}_content SET `introtext`=%s, `fulltext`=%s WHERE id=%s"
            args = (introtext, fulltext, id)
        elif introtext and fulltext is None or fulltext=="":
            sql = f"UPDATE {table_prefix} SET `introtext`=%s WHERE id=%s"
            args = (introtext, id)
        elif fulltext and introtext is None or introtext=="":
            sql = f"UPDATE {table_prefix}_content SET `fulltext`=%s WHERE id=%s"
            args = (fulltext, id)
        else:
            return False

        with connection.cursor() as cursor:
            cursor.execute(sql, args)
        connection.commit()
        return True
    except MySQLError as e:
        # logger.error(e)
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

def fix_text_matches(text_matches):
    return [i[0] if i[0] else i[1] for i in text_matches]
    # matches=[]
    # for i in  text_matches:
    #     if i[0] is not None and i[0]!="":
    #         matches.append(i[0])
    #     else:
    #         matches.append(i[1])
    # return matches

def find_urls(text):
    # ragax to find urls that present in anchor tags 
    anchor_tag_pattern=r"""<a\s+(?:[^>]*?\s+)?href=["']([^"']*)["']"""
    text_url_pattern=r"""\(((?<!href=["'])(?<!href=["']https:\/\/)(?<!>)(?:https?|ftp|sftp):\/\/[^\s<>"';]+|(?<!href=["']https:\/\/)(?<!href=["']http:\/\/)(?<!>)(?<!href=["'])www\.[^\s<>"';]+\.[^\s<>"';]+)\)|((?<!href=["'])(?<!href=["']https:\/\/)(?<!>)(?:https?|ftp|sftp):\/\/[^\s<>"';]+|(?<!href=["']https:\/\/)(?<!href=["']http:\/\/)(?<!>)(?<!href=["'])www\.[^\s<>"';]+\.[^\s<>"';]+)"""
    # text_url_pattern=r"""(?<!href=["'])(?<!href=["']https:\/\/)(?<!>)(?:https?|ftp|sftp):\/\/[^\s<>"';]+|(?<!href=["']https:\/\/)(?<!href=["']http:\/\/)(?<!>)(?<!href=["'])www\.[^\s<>"';]+\.[^\s<>"';]+""" 
    # pattern = r"""\b(?:(?:(?:(?:https?|ftp?|sftp?):\/\/)|(?:www\.))|(?:ftp:)|(?<=href="|href=\'))[^\s<>;]+\b[\/]?"""
    # pattern=r"""\b(?:(?:(?:(?:https?|ftp?|sftp?):\/\/)|(?:www\.))|(?:ftp:)|(?<=href="|href=\'|href="|href=\'))[^\s<>"&;]+(?:&amp;[^\s<>"&;?]+=[^\s<>"&;?]+)*\b[\/]?(?<!;q\s)(?!;<>)"""
    anchor_url_matches=re.findall(anchor_tag_pattern,text)
    text_url_tuple_matches=re.findall(text_url_pattern,text)
    text_url_matches=fix_text_matches(text_url_tuple_matches)
    matches=list(set(anchor_url_matches+text_url_matches))
    return matches


def process_broken_urls(html: str,logger:Logger,id:int,field:str,generic_nested_url_file:str):
    broken_links = find_broken_urls(html)
    updates=[]
    for correct_url, broken_url in broken_links.items():
        html = re.sub(broken_url, correct_url, html)
        logger.info(f'ID: {id} #COLUMN: {field} #URL: {broken_url} replaced with {correct_url}')
        updates.append(True)
        # data={"id":id,"field":field,"broken_url":broken_url,"correct_url":correct_url,"decompose_url":None,"url":None,"status_code":None,"action":"Replace with correct url"}
        # write_generic_modified_url_file(filename=generic_nested_url_file,data=data)
    return html,updates


def decompose_known_urls(html:str,logger:Logger,id:int,field:str,updates:list,generic_nested_url_file:str):
    all_urls = find_urls(html)
    soup=BeautifulSoup(html,'html.parser')
    data={"id":id,"field":field,"decompose_url":None,"url":None,"status_code":None,"action":None}
    for url in all_urls:
        dececode_url=ht.unescape(url)
        parsed_url = urlparse(url)
        if parsed_url.scheme in ['http','https']:
            domain = parsed_url.netloc
            domain=domain.lower()
            str_soup = str(soup)
            if domain in DECOMPOSE_URLS:
                a_tags = soup.find_all('a', attrs={'href': dececode_url})
                for tag in a_tags:
                    text=tag.text.strip()
                    updates.append(True)
                    if text and len(text)>0 and url not in text:
                        tag.replace_with(text)
                        logger.info(f'ID: {id} #COLUMN: {field} #URL: {url} replaced with {text}')
                    else:
                        tag.decompose()
                        logger.info(f'ID: {id} #COLUMN: {field} #URL: {url} replaced with {" "}')
                if len(a_tags)==0 and url in str_soup:
                    pattern = re.escape(url) + r'(\r\n|\n)'
                    if re.search(pattern, str_soup):
                        str_soup = re.sub(pattern, '', str_soup)
                    else:
                        str_soup = str_soup.replace(url, '')
                    logger.info(f'ID: {id} #COLUMN: {field} #URL: {url} replaced with {"null"}')
                    updates.append(True)
                    soup=BeautifulSoup(str_soup,'html.parser')
                data.update({"decompose_url":url,"action":"Decompose url"})
                write_generic_modified_url_file(filename=generic_nested_url_file,data=data)
        elif parsed_url.scheme in ['ftp']:
            domain = parsed_url.netloc
            domain=domain.lower()
            str_soup = str(soup)
            if domain in FTP_DECOMPOSE_URLS:
                a_tags = soup.find_all('a', attrs={'href': dececode_url})
                for tag in a_tags:
                    text=tag.text.strip()
                    updates.append(True)
                    if text and len(text)>0 and url not in text:
                        tag.replace_with(text)
                        logger.info(f'ID: {id} #COLUMN: {field} #URL: {url} replaced with {text}')
                    else:
                        tag.decompose()
                        logger.info(f'ID: {id} #COLUMN: {field} #URL: {url} replaced with {" "}')
                if len(a_tags)==0 and url in str_soup:
                    pattern = re.escape(url) + r'(\r\n|\n)'
                    if re.search(pattern, str_soup):
                        str_soup = re.sub(pattern, '', str_soup)
                    else:
                        str_soup = str_soup.replace(url, '')
                    logger.info(f'ID: {id} #COLUMN: {field} #URL: {url} replaced with {"null"}')
                    updates.append(True)
                    soup=BeautifulSoup(str_soup,'html.parser')
                data.update({"decompose_url":url,"action":"Decompose url"})
                write_generic_modified_url_file(filename=generic_nested_url_file,data=data)
        elif any(i in url for i in PREDETERMINE_LIST):
            url=url.split('?')[0]
            a_tags = soup.find_all('a',href=lambda href:href and url in href)
            for tag in a_tags:
                text=tag.text.strip()
                updates.append(True)
                if text and len(text)>0 and url not in text:
                    tag.replace_with(text)
                    logger.info(f'ID: {id} #COLUMN: {field} #URL: {url} replaced with {text}')
                else:
                    tag.decompose()
                    logger.info(f'ID: {id} #COLUMN: {field} #URL: {url} replaced with {" "}')
                data.update({"decompose_url":url,"action":" Decompose Predetermine List"})
                write_generic_modified_url_file(filename=generic_nested_url_file,data=data)


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
    url = url.replace('&gt', '').replace('&lt',"")
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


async def new_do_http_request(urls_obj,session,logger:Logger,id:int,image_urls:list):
    urls=list(urls_obj.keys())
    tasks=[]
    for url in urls:
        task = asyncio.create_task(new_check_http_broken_link(url=url, session=session,logger=logger,id=id))
        tasks.append(task)
    result = await asyncio.gather(*tasks)
    for response in result:
        if urls_obj[response['url']] in image_urls:
            is_image=True
        else:
            is_image=False
        redirect_url = response['redirect_url'] if response['is_redirect'] else None
        if not response['is_error'] or isinstance(response['status_code'],int):
            if response['status_code']< 400 or response['status_code'] in VALID_HTTP_STATUS_CODES:
                yield {'is_broken': False, 'status_code': response['status_code'], 'url': response['url'],'img':is_image,"redirected_url":redirect_url}
            else:
                yield {'is_broken': True, 'status_code': response['status_code'], 'url': response['url'],'img':is_image,"redirected_url":redirect_url}
        else:
            data=response['status_code']
            exception_type=str(data['type'])
            exception_message=data['message']
            if any(keyword in exception_type for keyword in ['ClientConnectorError','ClientConnectionError']):  
                if any(keyword in exception_message for keyword in ["Name or service not known","getaddrinfo failed","nodename nor servname","No address associated with hostname"]):
                    logger.error(f"#ID: {id} #URL {response['url']} Error: No service {exception_message}")
                    yield {'is_broken': True, 'status_code': 500, 'url': response['url'],'img':is_image,"redirected_url":redirect_url}
                else:
                    logger.warning(f"#ID: {id} #URL {response['url']} Error: Client connection error {exception_message}") 
                    yield {'is_broken': False, 'status_code': 'ConnectionError', 'url': response['url'],"img":is_image,"redirected_url":redirect_url}

            elif any(keyword in exception_type for keyword in ['ClientSSLError','ClientConnectorSSLError']):
                logger.warning(f"#ID: {id} #URL {response['url']} Error: SSLError {exception_message}")
                yield {'is_broken': False, 'status_code': 'SSLError', 'url': response['url'],"img":is_image,"redirected_url":redirect_url}

            elif any(keyword in exception_type for keyword in ['TimeoutError']):
                logger.warning(f"#ID: {id} #URL {response['url']}  Error: Timeout error {exception_message}")
                yield {'is_broken': False, 'status_code': 'Timeout', 'url': response['url'],'img':is_image,"redirected_url":redirect_url}
            else:
                logger.error(f'#ID: {id} #URL {url} Error: {exception_type}')
                yield {'is_broken': True, 'status_code': 500, 'url': response['url'],"img":is_image,"redirected_url":redirect_url}



def do_ftp_request(urls, logger: Logger, id: int):
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(check_ftp_broken_link, url=url, logger=logger,timeout=FTP_REQUEST_TIMEOUT): url for url in urls}
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

def check_ftp_urls( logger:Logger, id:int, updates:list,field:str, html: Optional[str] = None, urls:list=None,generic_nested_url_file:str=None,data:dict=None):
    for_more_check_urls = set()
    soup=BeautifulSoup(html,'html.parser')
    for result in do_ftp_request(urls=urls, logger=logger, id=id):
        url = result.get('url')
        if not result.get('is_broken', False):
            # Link is still existing - no need to do anything
            updates.append(False)
            logger.info(f'Skipped ID: {id} #COLUMN: {field} #FTP_URL: {url if url else ("null")} #STATUS_CODE: {result.get("status_code")}')
            data.update({"url":url,"status_code":result.get("status_code"),"action":"Do Ftp Request"})
            write_generic_modified_url_file(filename=generic_nested_url_file,data=data)
            continue
        if result.get('status_code')==404:
            decode_url=ht.unescape(url)
            a_tags = soup.find_all('a', attrs={'href': decode_url})
            str_soup=str(soup)
            for tag in a_tags:
                text = tag.text.strip()
                if text == url or len(text) == 0:
                    for_more_check_urls.add(url)
                    logger.info(f'ID: {id} #COLUMN: {field} #URL: {url if url else "(null)"} #STATUS_CODE: {result.get("status_code")} -Added for more for check urls')
                    # If the link text is also a URL, we should probably remove the entire link and link text, as it will also create a problem
                    # logger.info(f'ID: {id} #COLUMN: {field} #URL: {url if url else "(null)"} #STATUS_CODE: {result.get("status_code")} #TEXT: {"(null)" if len(text) == 0 else text} removed')
                    # tag.decompose()
                else:
                    for_more_check_urls.add(url)
                    logger.info(f'ID: {id} #COLUMN: {field} #URL: {url if url else "(null)"} #STATUS_CODE: {result.get("status_code")} -Added for more for check urls')
                    # Replace tag with tag text only
                    # tag.replace_with(text)
                    # logger.info(f'ID: {id} #COLUMN: {field} #URL: {url if url else "(null)"} #STATUS_CODE: {result.get("status_code")} - Replaced with #TEXT: {text}')
            if len(a_tags) == 0 and url in str_soup:
                for_more_check_urls.add(url)
                # pattern = re.escape(url) + r'(\r\n|\n)'
                # if re.search(pattern, str_soup):
                #     str_soup = re.sub(pattern, '', str_soup)
                # else:
                #     str_soup = str_soup.replace(url, '')
                updates.append(True)
                soup=BeautifulSoup(str_soup,'html.parser')
            updates.append(True)
            data.update({"url":url,"status_code":result.get("status_code"),"action":"Do Ftp Request Added into check urls"})
            write_generic_modified_url_file(filename=generic_nested_url_file,data=data)
        else:
            for_more_check_urls.add(url)
            data.update({"url":url,"status_code":result.get("status_code"),"action":"Do Ftp Request Added into check urls"})
            write_generic_modified_url_file(filename=generic_nested_url_file,data=data)
    return str(soup), updates,for_more_check_urls

async def update_redirected_url(url,result ,soup,updates,logger,field,id,redirected_file):
    result.update({"id":id})
    str_soup=str(soup)
    redirected_url=urlparse(result.get("redirected_url"))._replace(query=None).geturl()
    result.update({"redirected_url":redirected_url})
    decode_url=ht.unescape(url)
    a_tags = soup.find_all('a', attrs={'href': decode_url})
    for tag in a_tags:
        text=tag.text.strip()
        parsed_url=urlparse(result.get("redirected_url")).path
        if text==url:
            tag.string=parsed_url
        if not any(url.startswith(element) for element in ['http', 'https', 'www', 'ftp', 'ftps', "mailto:", "tel:", "#"]):
            tag['href']=parsed_url
            logger.info(f'ID:{id} #column {field} #URL {url} REDIRECTS TO {parsed_url} #STATUS_CODE: {result.get("status_code")}' )
        else:
            tag['href']=result.get("redirected_url")
            logger.info(f'ID:{id} #column {field} #URL {url} REDIRECTS TO {result.get("redirected_url")} #STATUS_CODE: {result.get("status_code")}' )
    if len(a_tags)==0 and url in str_soup:
        str_soup=str_soup.replace(url,result.get("redirected_url"))
        logger.info(f'ID:{id} #column {field} #URL {url} REDIRECTS TO {result.get("redirected_url")} #STATUS_CODE: {result.get("status_code")}' )
        soup=BeautifulSoup(str_soup,"html.parser")
    updates.append(True)
    write_redirect_urls(redirected_file,result)
    return soup,updates

async def check_http_urls(logger:Logger, id:int,field:str,updates:list,base_url:str,html:Optional[str]=None, urls:list=None,for_more_check_urls:set=None,image_urls:list=None,redirected_file:str=None,generic_nested_url_file:str=None,data:dict=None):
    soup=BeautifulSoup(html,'html.parser')
    str_soup=str(soup)
    urls_obj=get_double_https(urls)
    urls_obj = create_relative_urls(urls_obj,base_url)
    added_img_urls=set()
    if len(urls)!=0:
        async with aiohttp.ClientSession() as session:
            async for result in new_do_http_request(urls_obj=urls_obj, session=session, logger=logger, id=id,image_urls=image_urls):            
                parsed_url = result.get('url')
                url=urls_obj.get(str(parsed_url),"")
                if result.get("redirected_url") is not None and result.get('status_code')!=404:
                    soup,updates=await update_redirected_url(url,result,soup,updates,logger,field,id,redirected_file)
                    continue

                if result.get('img'):
                    if result.get('status_code') ==200:
                        logger.info(f'ID: {id} #URL: {parsed_url} #STATUS_CODE: {result.get("status_code")}')
                        data.update({"url":parsed_url,"status_code":result.get("status_code"),"action":"Do Http Request img URL"})
                    else:
                        added_img_urls.add(url)
                        data.update({"url":parsed_url,"status_code":result.get("status_code"),"action":"Added for more checking img url"})
                        logger.info(f'ID: {id} #COLUMN: {field} #URL: {parsed_url} added as img url')
                    write_generic_modified_url_file(filename=generic_nested_url_file,data=data)  
                    continue

                if not result.get('is_broken', False):
                    if check_https_urls(url):
                        decode_url=ht.unescape(url)
                        a_tags = soup.find_all('a', attrs={'href': decode_url})
                        for tag in a_tags:
                            tag['href']=parsed_url 
                            logger.info(f'ID: {id} #COLUMN: {field} #URL: {url} replaced with {parsed_url}')
                        if len(a_tags)==0 and url in str_soup:
                            str_soup=str_soup.replace(url,parsed_url) 
                            logger.info(f'ID: {id} #COLUMN: {field} #URL: {url} replaced with {parsed_url}')
                            soup=BeautifulSoup(str_soup,"html.parser")
                        updates.append(True)
                        data.update({"url":parsed_url,"status_code":result.get("status_code"),"action":"Do Http Request"}) 
                        write_generic_modified_url_file(filename=generic_nested_url_file,data=data)
                        continue

                    updates.append(False)
                    if result.get('status_code') in VALID_HTTP_STATUS_CODES:
                        logger.warning(f'ID: {id} #COLUMN: {field} #URL: {parsed_url} #STATUS_CODE: {result.get("status_code")}')
                        data.update({'url':parsed_url,"status_code":result.get("status_code"),"action":"Do Http Request"})
                        write_generic_modified_url_file(filename=generic_nested_url_file,data=data)
                    else:
                        if result.get('status_code') in STATUS_CODES_FOR_FURTHER_CHECK:
                            logger.info(f'ID: {id} #COLUMN: {field} #URL: {url} added for more checking')
                            for_more_check_urls.add(url)
                            data.update({'url':parsed_url,"status_code":result.get("status_code"),"action":"Do Http Request Added for more check"})
                        else:
                            logger.info(f'Skipped ID: {id} #COLUMN: {field} #URL: {parsed_url} #STATUS_CODE: {result.get("status_code")}')
                            data.update({'url':parsed_url,"status_code":result.get("status_code"),"action":"Do Http Request"})
                        write_generic_modified_url_file(filename=generic_nested_url_file,data=data)
                    continue
                
                
                if result.get('status_code')==404:
                    decode_url=ht.unescape(url)
                    a_tags = soup.find_all('a', attrs={'href': decode_url})
                    for tag in a_tags:
                        text = tag.text.strip()
                        if text == url or len(text) == 0:
                            for_more_check_urls.add(url)
                            logger.info(f'ID: {id} #COLUMN: {field} #URL: {url if url else "(null)"} #STATUS_CODE: {result.get("status_code")} - Added for more check')
                            # tag.decompose()
                        else:
                            for_more_check_urls.add(url)
                            # tag.replace_with(text)
                            logger.info(f'ID: {id} #COLUMN: {field} #URL: {url if url else "(null)"} #STATUS_CODE: {result.get("status_code")} -  Added for more check')
                            # logger.info(f'ID: {id} #COLUMN: {field} #URL: {url if url else "(null)"} #STATUS_CODE: {result.get("status_code")} - Replaced with #TEXT: {text}')
                    if len(a_tags) == 0 and url in str_soup:
                        for_more_check_urls.add(url)
                        logger.info(f'Skipped ID: {id} #COLUMN: {field} #URL: {parsed_url} #STATUS_CODE: {result.get("status_code")} -  Added for more check')
                        # pattern = re.escape(url) + r'(\r\n|\n)'
                        # if re.search(pattern, str_soup):
                        #     str_soup = re.sub(pattern, '', str_soup)
                        # else:
                        #     str_soup = str_soup.replace(url, '')
                        # logger.info(f'Skipped ID: {id} #COLUMN: {field} #URL: {parsed_url} #STATUS_CODE: {result.get("status_code")} #Replace with {"NULL"}')
                        soup=BeautifulSoup(str_soup,"html.parser")
                    updates.append(False)
                    data.update({'url':parsed_url,"status_code":result.get("status_code"),"action":"Do Http Request -Added into more urls"})
                else:
                    for_more_check_urls.add(url)
                    logger.info(f'ID: {id} #COLUMN: {field} #URL: {parsed_url} added for more checking')
                    data.update({'url':parsed_url,"status_code":result.get("status_code"),"action":"Do Http Request-Added into more urls"})
                write_generic_modified_url_file(filename=generic_nested_url_file,data=data)
    return str(soup),updates,for_more_check_urls,added_img_urls

def skip_check_sites(html,logger:Logger,generic_nested_url_file:str,data:dict):
    all_urls = find_urls(html)
    remaining_urls=[]
    for url in all_urls:
        if url.startswith('#') or urlparse(url).netloc in SKIP_CHECK_SITES or urlparse(url).scheme in ["mailto", "tel"]:
            logger.info(f"{url} is skiped for checking:- present in SKIP_CHECK_SITES ")
            data.update({"url":url,'action':"Skipped url"})
            write_generic_modified_url_file(filename=generic_nested_url_file,data=data)
            continue
        remaining_urls.append(url)
    return remaining_urls

def img_urls(html):
    img_tag_regex = r'<img[^>]+src="([^">]+)"'
    matches=re.findall(img_tag_regex,html)
    return matches



def check_is_url_valid(html:str, logger:Logger, id:int,field:str,base_url:str,updates:list,redirected_file:str,generic_nested_url_file:str):
    data={"id":id,"field":field,"decompose_url":None,"url":None,"status_code":None,"action":None}
    all_urls=skip_check_sites(html,logger,generic_nested_url_file,data)
    image_urls=img_urls(html)
    all_urls=list(set(all_urls+image_urls))
    ftp_urls = list(filter(lambda x: is_ftp_links(x), all_urls))
    http_urls = list(filter(lambda x: not is_ftp_links(x), all_urls))
    html,updates,for_more_check_urls = check_ftp_urls(html=html,urls= ftp_urls, logger=logger, id=id,field=field,updates=updates,generic_nested_url_file=generic_nested_url_file,data=data)
    html,updates,for_more_check_urls,added_img_urls = asyncio.run(check_http_urls(html=html, urls=http_urls, logger=logger, id=id,field=field,updates=updates,base_url=base_url,for_more_check_urls=for_more_check_urls,image_urls=image_urls,redirected_file=redirected_file,generic_nested_url_file=generic_nested_url_file,data=data))
    return html,any(updates),for_more_check_urls,added_img_urls

def process_html_text(logger: Logger, id: int, field: str, html: Optional[str] = None, base_url: str = None,redirected_file:str=None,generic_nested_url_file:str=None):
    try:
        for_more_check_urls = set()
        if html is None or len(html) == 0:
            return None, False, for_more_check_urls,[]
        html,updates = process_broken_urls(html,logger=logger,id=id,field=field,generic_nested_url_file=generic_nested_url_file)
        html,updates = decompose_known_urls(html,logger=logger,id=id,field=field,updates=updates,generic_nested_url_file=generic_nested_url_file)
        html,updates,for_more_check_urls,added_img_urls=check_is_url_valid(html,logger=logger,id=id,field=field,base_url=base_url,updates=updates,redirected_file=redirected_file,generic_nested_url_file=generic_nested_url_file)
        return html,updates,for_more_check_urls,added_img_urls
    except Exception as e:
        logger.exception(e)
        raise e


def do_remove_url(record: Dict[str, Any], logger: Logger, base_url: str,redirected_file:str,generic_nested_url_file:str):
    id = record.get("id")
    introtext = record.get("introtext")
    introtext_json_data = introtext.strip().strip("\\")
    if introtext_json_data.startswith("{") and introtext_json_data.endswith("}"):
        logger.info(f"Skipped ID: {id} - introtext is a json data")
        adjusted_introtext, need_update_introtext, intro_timeout_urls = None, None, []
    else:
        logger.info(f"processing  {id} - introtext is not JSON, proceeding further to check HTML")
        adjusted_introtext, need_update_introtext, intro_timeout_urls,intro_img_urls = process_html_text(
            logger=logger, id=id, field="introtext", html=introtext, base_url=base_url,redirected_file=redirected_file,generic_nested_url_file=generic_nested_url_file
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
        adjusted_fulltext, need_update_fulltext, full_timeout_urls, full_img_urls= process_html_text(
            logger=logger, id=id, field="fulltext", html=fulltext, base_url=base_url,redirected_file=redirected_file,generic_nested_url_file=generic_nested_url_file
        )
    if adjusted_introtext is None and adjusted_fulltext is None:
        logger.info(
            f"Skipped ID: {id} - Not found any URLs in both introtext, fulltext fields"
        )
        return None, None, any([need_update_introtext, need_update_fulltext]), None,None

    return (
        adjusted_introtext if adjusted_introtext else introtext,
        adjusted_fulltext if adjusted_fulltext else fulltext,
        any([need_update_introtext, need_update_fulltext]),
        intro_timeout_urls.union(full_timeout_urls),
        intro_img_urls.union(full_img_urls)
    )




shared_counter_lock = threading.Lock()
shared_counter = 0
def update_shared_counter(value):
    global shared_counter
    with shared_counter_lock:
        shared_counter += value

def get_shared_counter_value():
    global shared_counter
    with shared_counter_lock:
        return shared_counter


def get_db_connection(config,logger):
    try:
        # Connect to the database
        connection= pymysql.connect(
            host=config.get("mysql", "host"),
            port=int(config.get("mysql", "port")),
            user=config.get("mysql", "user"),
            password=config.get("mysql", "password"),
            database=config.get("mysql", "database"),
            cursorclass=pymysql.cursors.DictCursor,
        )
        return connection
    except MySQLError as e:
        logger.error(e)
        raise e

def process_record(records, log_file, base_url, timeout_file,nested_img_file,config, commit,total,log_level,redirected_file,table_prefix,generic_nested_url_file)-> tuple:
   
    logger = get_logger(name=log_file, log_file=log_file,log_level=log_level) 
    connection=get_db_connection(config,logger)
    counter=0 # Flag to track if any update fails
    thread_id=threading.get_ident()
    for record in records:
        try:
            update_shared_counter(1)
            shared_counter_value = get_shared_counter_value()
            logger.info(f'Multi-Thread script (Process ID : {thread_id}): Processing ID :{record.get("id")}  {"*"*10}  {shared_counter_value}/{total} - {percentage(shared_counter_value,total)}')
           
            # logger.info(
            #             f'{"*"*20} Processing ID: {record.get("id")} {"*"*20} ({counter}/{total} - {percentage(counter, total)})'
            #         )
            introtext, fulltext, is_update, timeout_urls,img_urls = do_remove_url(
                record=record, logger=logger, base_url=base_url,redirected_file=redirected_file,generic_nested_url_file=generic_nested_url_file
            )

            if timeout_urls and len(timeout_urls) > 0:
                write_file(
                    filename=timeout_file,
                    id=record.get("id"),
                    urls=timeout_urls,
                )
            if img_urls and len(img_urls)>0:
                write_img_urls(filename=nested_img_file,
                               id=record.get('id'),
                               urls=img_urls
                               )
            if is_update is False:
                continue
                # Set the flag to True but continue processing other records
                # is_any_update_failed = True
            else:
                if commit:
                    succeed = do_update(
                        connection=connection,
                        logger=logger,
                        id=record.get("id"),
                        introtext=introtext,
                        fulltext=fulltext,
                        table_prefix=table_prefix
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
    shared_counter_value = get_shared_counter_value()
    return current_id,shared_counter_value

    


def get_data_chunk(start, chunk_size,connection,table_prefix):
    offset = start  
    limit = chunk_size  
    sql=f"SELECT c.id, c.introtext, c.fulltext FROM {table_prefix}_content AS c LEFT JOIN {table_prefix}_categories cat ON cat.id = c.catid WHERE c.state = 1 AND cat.published = 1 ORDER BY c.id  LIMIT %s OFFSET %s"
    with connection.cursor() as cursor:
        cursor.execute(sql, (limit, offset))
        results = cursor.fetchall()
        return results




def main(commit: bool = False, id: Optional[int] = 0,log_level:bool=False):
    config = configparser.ConfigParser(interpolation=None)
    config.read(os.path.join(os.path.dirname(__file__), "config.ini"))

    log_file = config.get("script-01", "log_file")
    table_prefix=config.get("script-01","table_prefix")
    store_state_file = config.get("script-01", "store_state_file")
    timeout_file = config.get("script-01", "timeout_file")
    img_file = config.get("script-01", "img_csv_file")
    redirected_file=config.get("script-01","redirected_url_file")
    generic_modified_file=config.get("script-01","generic_modified_url_file")
    limit: int = config["script-01"].getint("limit",0)
    base_url: str = config.get("script-01", "base_url")
    offset:int=config["script-01"].getint("offset",0)

    logger: Logger = get_logger(name=log_file, log_file=log_file,log_level=log_level)

    connection=get_db_connection(config,logger)
    
    if limit>0:
        sql=f"SELECT COUNT(*) as total FROM (SELECT c.id FROM {table_prefix}_content c LEFT JOIN {table_prefix}_categories cat ON cat.id = c.catid WHERE c.state = 1 AND cat.published = 1 LIMIT {limit} ) AS limited_rows"
        # sql = f"SELECT count(c.id) as total FROM {table_prefix}_content c LEFT JOIN {table_prefix}_categories cat ON cat.id = c.catid WHERE c.state = 1 AND cat.published = 1 LIMIT {limit}"  
    else:
        sql=f"SELECT count(c.id) as total FROM {table_prefix}_content c LEFT JOIN {table_prefix}_categories cat ON cat.id = c.catid WHERE c.state = 1 AND cat.published = 1 "
    with connection.cursor() as cursor:
        cursor.execute(sql)
        result = cursor.fetchone()
    
    total = result.get("total") if id == 0 else 1 
    # else:
    #     total=limit if id==0 else 1
    chunk_size=1
    core_count=multiprocessing.cpu_count()
    if total>core_count:
        chunk_size=total//core_count
    data_chunks=[]
    all_data=False
    counter=0
    

    while True:
        try:
            if id > 0:
                sql = f"SELECT c.id, c.introtext, c.fulltext FROM {table_prefix}_content AS c WHERE id =%s"
                args = id
                with connection.cursor() as cursor:
                    cursor.execute(sql, args)
                    result = cursor.fetchall()
            else:
                all_data=True
                for start in range(offset, total+offset, chunk_size):
                    data_chunk = get_data_chunk(start, chunk_size,connection,table_prefix)
                    data_chunks.append(data_chunk)
                chunk_completion = {i: False for i in range(len(data_chunks))}
                nested_log_files = [f"process_{i}_log.json"for i in range(len(data_chunks))]
                nested_timeout_files=[f'process_{i}_timeout.json' for i in range(len(data_chunks))]
                nested_imgcsv_files=[f'Thread_{i}_imgcsv.csv' for i in range(len(data_chunks))]
                redirect_urls_files=[f'Thread_{i}_redirect_url.json' for i in range((len(data_chunks)))]
                generic_nested_modified_file=[f'Thread_{i}_generic_url_file.json' for i in range((len(data_chunks)))]
                with ThreadPoolExecutor() as executor:
                    futures = executor.map(process_record, data_chunks, nested_log_files, [base_url] * len(data_chunks), nested_timeout_files,nested_imgcsv_files, [config] * len(data_chunks), [commit] * len(data_chunks),[total] *len(data_chunks),[log_level]*len(data_chunks),redirect_urls_files,[table_prefix]*len(data_chunks),generic_nested_modified_file)
                for future in futures:
                    i,counter = future
                    for idx,chunk in enumerate(data_chunks):
                        if chunk[-1]['id']==i:
                            chunk_completion[idx] = True   

                for i, completed in chunk_completion.items():
                    if completed:
                        logger.info(f'{"="*20}  chunk {i} records have been processed {"="*20}')
                    else:
                        print(f"Chunk {i} is still processing")
                concatenate_timeout_files(nested_timeout_files,timeout_file)
                concatenate_img_csv_files(nested_imgcsv_files,img_file)
                concatenate_log_files(nested_log_files,log_file)
                concatenate_redirected_urls_file(redirect_urls_files,redirected_file)
                concatenate_generic_modfiled_url_file(generic_nested_modified_file,generic_modified_file)
                break  
 
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
                        introtext, fulltext, is_update, timeout_urls,img_urls = do_remove_url(
                            record=record, logger=logger, base_url=base_url,redirected_file=redirected_file,generic_nested_url_file=generic_modified_file
                        )
                        if timeout_urls and len(timeout_urls) > 0:
                            write_file(
                                filename=timeout_file,
                                id=record.get("id"),
                                urls=timeout_urls,
                            )
                        if img_urls and len(img_urls)>0:
                            write_img_urls(filename=img_file,
                                        id=record.get('id'),
                                        urls=img_urls
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
                                table_prefix=table_prefix
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

                
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", action="store_true", help="Update the database")
    parser.add_argument("--id", default=0, type=int, help="Check for specific ID")
    parser.add_argument('--q',action="store_true", help=" To hide looging in console")

    args = parser.parse_args()
    is_commit = args.commit
    specific_id = args.id
    hide_log=args.q

    main(commit=is_commit, id=specific_id,log_level=hide_log)
