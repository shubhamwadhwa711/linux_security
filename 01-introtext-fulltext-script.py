# -*- coding: utf-8 -*-
import requests
import lxml
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

from pymysql import MySQLError
from ftplib import all_errors
# import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
from typing import Dict, Any, Optional
import copy

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

from utils import (
    get_logger,
    timeit,
    current_state,
    percentage,
    check_http_broken_link,
    check_ftp_broken_link,
    check_url_against_domains,
    write_file,
    DECOMPOSE_URLS,
    HTTP_REQUEST_TIMEOUT,   
    FTP_REQUEST_TIMEOUT,
    VALID_HTTP_STATUS_CODES,
    STATUS_CODES_FOR_FURTHER_CHECK,
    SKIP_CHECK_SITES,
)


@timeit
def do_update(connection: Connection, logger: Logger, id, introtext: Optional[str] = None, fulltext: Optional[str] = None):
    try:
        if introtext is None and fulltext is None:
            return False

        if introtext and fulltext:
            sql = 'UPDATE xu5gc_content SET `introtext`=%s, `fulltext`=%s WHERE id=%s'
            args = (introtext, fulltext, id)
        elif introtext and fulltext is None:
            sql = 'UPDATE xu5gc_content SET `introtext`=%s WHERE id=%s'
            args = (introtext, id)
        elif fulltext and introtext is None:
            sql = 'UPDATE xu5gc_content SET `fulltext`=%s WHERE id=%s'
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


# @timeit
def do_http_request(urls, logger: Logger, id: int):
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(check_http_broken_link, url=url, logger=logger, id=id, timeout=HTTP_REQUEST_TIMEOUT): url for url in urls}
        for future in as_completed(futures):
            url = futures[future]
            try:
                response = future.result()
            except requests.Timeout as e:
                logger.warning(f'#ID: {id} #URL {url} Error: Timeout {str(e)}')
                yield {'is_broken': False, 'status_code': 'Timeout', 'url': url}
            except requests.exceptions.SSLError as e:
                logger.warning(f'#ID: {id} #URL {url} Error: SSLError {str(e)}')
                yield {'is_broken': False, 'status_code': 'SSLError', 'url': url}
            except requests.exceptions.ConnectionError as e:
                if ("[Errno 11001] getaddrinfo failed" in str(e) or     # Windows
                    "[Errno -2] Name or service not known" in str(e) or # Linux
                    "[Errno 8] nodename nor servname" in str(e) or
                    "[Errno -5] No address associated with hostname" in str(e)):      # OS X
                    logger.error(f'#ID: {id} #URL {url} Error: {str(e)}')
                    yield {'is_broken': True, 'status_code': 500, 'url': url}
                else:
                    logger.warning(f'#ID: {id} #URL {url} Error: {str(e)}')
                    yield {'is_broken': False, 'status_code': 'ConnectionError', 'url': url}
            except Exception as e:
                logger.error(f'#ID: {id} #URL {url} Error: {str(e)}')
                logger.error(str(e))
                yield {'is_broken': True, 'status_code': 500, 'url': url}
            else:
                if response.status_code < 400 or response.status_code in VALID_HTTP_STATUS_CODES:
                    yield {'is_broken': False, 'status_code': response.status_code, 'url': url}
                else:
                    yield {'is_broken': True, 'status_code': response.status_code, 'url': url}

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

def find_broken_url_in_tags(a_tags):
    for a in a_tags:
        href = a.get('href', None)
        text = a.text.strip()

        if href is None:
            # link does not contain href
            yield {'tag': a, 'text': text, 'can_replace': True}
        elif href.startswith('mailto:') or '@' in href:
            # link contains email address
            continue
        elif href.startswith('ftp'):
            # link contains ftp address
            # continue
            yield {'tag': a, 'text': text, 'can_replace': False, 'ftp': True}
        elif href.startswith('#'):
            continue
        elif any(site in href for site in SKIP_CHECK_SITES):
            # Skipped checking if site is in SKIP_CHECK_SITES
            continue
        else:
            try:
                is_valid_url = validators.url(href)
                if is_valid_url:
                    # link contains href, valid url - request to check status code
                    yield {'tag': a, 'text': text, 'can_replace': False}
                elif isinstance(is_valid_url, validators.ValidationFailure):
                    yield {'tag': a, 'text': text, 'can_replace': False}
                else:
                    # link contains href, but invalid url
                    yield {'tag': a, 'text': text, 'can_replace': True}
            except Exception as e:
                    yield {'tag': a, 'text': text, 'can_replace': True}

def find_ftp_links(text):
    # Define the regex pattern for FTP links
    # pattern = r"ftp://\S+"
    pattern= r"""(?<!href="|href=\')(ftp[s]?:\/\/(?:[^\s<>")'\(]+|www\.[^\s<>")'\(]+)[^\s<>")'\(]+)(?![^<]*>|[^<>]*<\/a>)"""
    # Find all matches in the text
    matches = re.findall(pattern, text)
    return matches

def find_ftp_link(text, ftp_link):
    pattern = re.escape(ftp_link)  # Escape special characters in the FTP link
    matches = re.findall(pattern, text)
    return matches

def find_text_links(text):
    # Regular expression pattern to match HTTP and HTTPS links not within anchor tags
    # pattern = r'(?<!href=")(?P<url>(?:http|https)://[^\s<>"]+|www\.[^\s<>"]+)'
    # pattern = r'(?<!href="|href=\')(http[s]?:\/\/(?:[^\s<>"]+|www\.[^\s<>"]+))(?![^<]*>|[^<>]*<\/a>)'
    # pattern = r'(?<!href="|href=\')(http[s]?:\/\/(?:[^\s<>"]+|www\.[^\s<>"]+)\s{0,2}[^\s<>"]+)(?![^<]*>|[^<>]*<\/a>)'
    # pattern = r"""(?<!href="|href=\')(http[s]?:\/\/(?:[^\s<>")'\(]+|www\.[^\s<>")'\(]+)[^\s<>")'\((&gt);]+(?:\.[^\s<>")'\(&gt;]+)?(?![^<]*>|[^<>]*<\/a>))"""
    # pattern = r"""(?<!href="|href=\')(http[s]?:\/\/(?:[^\s<>")'\(]+|www\.[^\s<>")'\(]+)[^\s<>")'\(]+)(?![^<]*>|[^<>]*<\/a>)"""
    # pattern = r"""(?<!href="|href=\')(http[s]?:\/\/(?:[^\s<>")'\(]+|www\.[^\s<>")'\(]+\s{0,2})[^\s<>")'\(]+)(?![^<]*>|[^<>]*<\/a>)"""
    # pattern = r"""(?<!href="|href=\')(http[s]?:\/\/(?:[^\s<>")'\(]+|www\.[^\s<>")'\(]+)[^\s<>")'\(\*]+)(?![^<]*>|[^<>]*<\/a>)""" 
    pattern=r"""(?<!href="|href=\')(http[s]?:\/\/(?:[^\s<>")'\(;]+|www\.[^\s<>")'\(]+)[^\s<>")'\(\*;]+)(?![^<]*>|[^<>]*<\/a>)"""
    # to consider one space between the url
    # Find all matches
    matches = re.findall(pattern, text)
    # if not matches:
    #     pattern = r'(?<!href=")(?P<url>(?:http|https)://[^\s<>"]+|www\.[^\s<>"]+)'
    #     matches = re.findall(pattern, text)
    # cleaned_matches = [re.sub(r'^(?:http|https)://', '', url) for url in matches]
    # Return the list of links
    return matches

def find_broken_text_links(text):
        # pattern=r"""(?<!href="|href=\')(http[s]?:\/\/(?:[^\s<>")'\(]+|www\.[^\s<>")'\(]+)-\n{1}[^\s<>")'\(\*]+)(?![^<]*>|[^<>]*<\/a>)"""
        pattern=r"""(?<!href="|href=\')(http[s]?:\/\/(?:[^\s<>")'\(;]+|www\.[^\s<>")'\(]+)-\n{1}[^\s<>")'\(\*;]+)(?![^<]*>|[^<>]*<\/a>)"""
        matches=re.findall(pattern,text)
        broken_links={}
        for m in matches:
            joined_url=re.sub(r'\n', '',m)
            broken_links[joined_url]=m
        return broken_links

# added function to remove parenthesis or periods and &gt

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
        url=strip_trailing_in_anchor(url)
        obj[url]=original_url
    return obj

#added a function to remove whitespaces  into the text links
def remove_escape_chars_from_url(url):
    # Remove whitespace characters from the URL
    # url = re.sub(r'\s', '', url)
    url = re.sub(r'\n', '', url)
    return url


def normalize_urls(url):
    url = remove_escape_chars_from_url(url)
    url = strip_trailing_in_anchor(url)
    return url

def find_www_links(text):
    # Regular expression pattern to match HTTP and HTTPS links not within anchor tags
    pattern = r'(?<!href=")(\bwww\.\S+)'
    # Find all matches
    matches = re.findall(pattern, text)
    # Return the list of links
    return matches

# @timeit
def extract_a_tag_in_html(logger: Logger, id: int, field: str, html: Optional[str] = None, base_url: str = None):
    try:
        for_more_check_urls = set()
        if html is None or len(html) == 0:
            return None, False, for_more_check_urls

        # soup = BeautifulSoup(html, 'lxml')
        soup=BeautifulSoup(html,'html.parser')
        a_tags = soup.find_all('a')
        # if len(a_tags) == 0:
        #     return None, False, for_more_check_urls

        http_urls = []
        ftp_urls = []
        protocol_urls = []
        updates = []

        for a_tag in find_broken_url_in_tags(a_tags=a_tags):
            if a_tag is None:
                continue

            tag = a_tag.get('tag')
            text = a_tag.get('text')
            can_replace = a_tag.get('can_replace', False)
            is_fpt_link = a_tag.get('ftp', False)
            is_protocol_failiure = a_tag.get('protocol', False)

            url = tag.get('href')
            if can_replace:
                updates.append(True)
        #  added new condition to handle if href attribute is not present in the anchor tag
                if not url:
                    logger.info(f'ID: {id} #COLUMN: {field} #URL: {url if url else "(null)"} - Skipping Anchor Tag as no href attribute found')
                    continue
                    # tag.replace_with(text)
                    # logger.info(f'ID: {id} #COLUMN: {field} #URL: {url if url else "(null)"} - Replaced with #TEXT: {text}')
                elif len(text) > 0 and url not in text:
                    tag.replace_with(text)
                    logger.info(f'ID: {id} #COLUMN: {field} #URL: {url if url else "(null)"} - Replaced with #TEXT: {text}')
                else:
                    tag.decompose()
                    logger.info(f'ID: {id} #COLUMN: {field} #URL: {url if url else "(null)"} #TEXT: (null) removed')
                # if is_protocol_failiure:
                #     tag.replace_with(text)
            else:
                if is_fpt_link:
                    ftp_urls.append(url)
                # elif is_protocol_failiure:
                #     protocol_urls.append(url)
                else:
                    if not url.startswith('http'):
                        url = f'{base_url}/{url[1:] if url.startswith("/") else url}'
                    http_urls.append(url)
      

        if len(http_urls) > 0:
            http_urls_obj=get_double_https(http_urls)
            http_urls=list(http_urls_obj.keys())
            
            # http_urls = []
            # http_urls = [strip_trailing_chars(url) for url in http_urls]
            for result in do_http_request(urls=http_urls, logger=logger, id=id):
                parsed_url = result.get('url')
                url=http_urls_obj[parsed_url]
                if not result.get('is_broken', False):
                    if check_https_urls(url):
                        a_tags = soup.find_all('a', attrs={'href': url})
                        for tag in a_tags:
                            tag['href']=parsed_url 
                            logger.info(f'ID: {id} #COLUMN: {field} #URL: {url} replaced with {parsed_url}') 
                        updates.append(True)
                        continue
                    # Link is still existing - no need to do anything
                    updates.append(False)
                    if result.get('status_code') in VALID_HTTP_STATUS_CODES:
                        logger.warning(f'ID: {id} #COLUMN: {field} #URL: {parsed_url} #STATUS_CODE: {result.get("status_code")}')
                    else:
                        if result.get('status_code') in STATUS_CODES_FOR_FURTHER_CHECK:
                            logger.info(f'ID: {id} #COLUMN: {field} #URL: {parsed_url} added for more checking')
                            for_more_check_urls.add(url)
                        else:
                            logger.info(f'Skipped ID: {id} #COLUMN: {field} #URL: {parsed_url} #STATUS_CODE: {result.get("status_code")}')
                    continue

                a_tags = soup.find_all('a', attrs={'href': url})
                if len(a_tags) == 0:
                    continue

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
        
        def decompose_urls(text):
            decompose_broken_text_links=find_broken_text_links(html)
            decompose_broken_text_links=decompose_broken_text_links.keys()
            decompose_text_links=find_text_links(modified_html)
            decompose_text_links.extend(decompose_broken_text_links)
            results=[check_url_against_domains(url) for url in decompose_text_links]
            return results,decompose_text_links

        modified_html = str(soup)
        ftp_links = find_ftp_links(modified_html)
        ftp_urls.extend(ftp_links)
        ftp_urls = [normalize_urls(url) for url in ftp_urls]
        if len(ftp_urls) > 0:
            correct_ftp=[]
            results=[check_url_against_domains(url) for url in ftp_urls]
            for result,url in zip(results,ftp_urls):
                if result:
                    updates.append(True)
                    a_tags = soup.find_all('a', attrs={'href': url})
                    if len(a_tags)>0:
                        for tag in a_tags:
                            text=tag.text.strip()
                            if text==url or len(text)==0:
                                tag.decompose()
                                logger.info(f'ID: {id} #COLUMN: {field} #FTP_URL: {url if url else ("null")} #present in DECOMPOSE  FTP URLS  #TEXT: {"(null)" if len(text) == 0 else text} removed')
                            else:
                                tag.replace_with(text)
                                logger.info(f'ID: {id} #COLUMN: {field} #FTP_URL: {url if url else ("null")} #present in DECOMPOSE  FTP URLS  #TEXT: Replaced with #TEXT: {text}')
                    else:
                        modified_html=re.sub(re.escape(url)," ",modified_html)
                        logger.info(f'ID: {id} #COLUMN: {field} #FTP_URLS: {url} is Replaced with null')
                else:
                    correct_ftp.append(url)


            if len(correct_ftp)>0:
                logger.info(f'ID: {id} #COLUMN: {field} #FTP_URLS: {correct_ftp} will be checking')
                for result in do_ftp_request(urls=correct_ftp, logger=logger, id=id):
                    url = result.get('url')
                    if not result.get('is_broken', False):
                        # Link is still existing - no need to do anything
                        updates.append(False)
                        logger.info(f'Skipped ID: {id} #COLUMN: {field} #FTP_URL: {url if url else ("null")} #STATUS_CODE: {result.get("status_code")}')
                        continue

                    a_tags = soup.find_all('a', attrs={'href': url})
                    if len(a_tags) > 0:
                        updates.append(True)
                        for tag in a_tags:
                            text = tag.text.strip()
                            if text == url or len(text) == 0:
                                # If the link text is also a URL, we should probably remove the entire link and link text, as it will also create a problem
                                tag.decompose()
                                logger.info(f'ID: {id} #COLUMN: {field} #FTP_URL: {url if url else ("null")} #STATUS_CODE: {result.get("status_code")} #TEXT: {"(null)" if len(text) == 0 else text} removed')
                            else:
                                # Replace tag with tag text only
                                tag.replace_with(text)
                                logger.info(f'ID: {id} #COLUMN: {field} #FTP_URL: {url if url else ("null")} #STATUS_CODE: {result.get("status_code")} - Replaced with #TEXT: {text}')

                    found = find_ftp_link(modified_html, url)
                    if found:
                        updates.append(True)
                        modified_html = re.sub(re.escape(url), ' ', modified_html)
                        logger.info(f'ID: {id} #COLUMN: {field} #FTP_URL: {url if url else ("null")} - Replaced with #TEXT: (null)')

        http_broken_text_links=find_broken_text_links(html)
        
        if len(http_broken_text_links)>0:
            broken_urls=http_broken_text_links.keys()
            broken_url_startwith_http=[normalize_urls(url) for url in broken_urls]
            for result in do_http_request(urls=broken_url_startwith_http, logger=logger, id=id):
                url = result.get('url')
                exact_broken_url=http_broken_text_links[url]
                if not result.get('is_broken', False):
                    updates.append(True)
                    modified_html = re.sub(exact_broken_url,url, modified_html)
                    logger.warning(f'ID: {id} #COLUMN: {field} #URL: {exact_broken_url} replaced with {url}')
                    if result.get('status_code') in VALID_HTTP_STATUS_CODES:
                        # modified_html = re.sub(re.escape(original_url), url, modified_html)
                        logger.warning(f'ID: {id} #COLUMN: {field} #URL: {url} #STATUS_CODE: {result.get("status_code")}')
                    else:
                        if result.get('status_code') in STATUS_CODES_FOR_FURTHER_CHECK:
                            logger.info(f'ID: {id} #COLUMN: {field} #URL: {url} added for more checking')
                            for_more_check_urls.add(url)
                        else:
                            logger.info(f'Skipped ID: {id} #COLUMN: {field} #URL: {url} #STATUS_CODE: {result.get("status_code")}')
                    continue
            
                updates.append(True)
                modified_html = re.sub(re.escape(exact_broken_url), ' ', modified_html)
                logger.info(f'ID: {id} #COLUMN: {field} #URL: {url if url else ("null")} #STATUS_CODE: {result.get("status_code")} - Replaced with #TEXT: (null)')
                
        http_text_links = find_text_links(modified_html)
  
        if len(http_text_links) > 0:
            url_startwith_www = [url for url in http_text_links if url.startswith('www')]
            url_startwith_http = [url for url in http_text_links if url not in url_startwith_www]
            url_startwith_http = [normalize_urls(url) for url in url_startwith_http]

            # url_startwith_http =[strip_trailing_chars(url) for url in url_startwith_http]
            # url_startwith_http =[remove_whitespace_from_url(url) for url in url_startwith_http]
            for result in do_http_request(urls=url_startwith_http, logger=logger, id=id):
                url = result.get('url')
                # original_url=f'https://{url}'
                if not result.get('is_broken', False):
                    updates.append(False)
                    if result.get('status_code') in VALID_HTTP_STATUS_CODES:
                        # modified_html = re.sub(re.escape(original_url), url, modified_html)
                        logger.warning(f'ID: {id} #COLUMN: {field} #URL: {url} #STATUS_CODE: {result.get("status_code")}')
                    else:
                        if result.get('status_code') in STATUS_CODES_FOR_FURTHER_CHECK:
                            # modified_html = re.sub(re.escape(original_url), '', modified_html)
                            logger.info(f'ID: {id} #COLUMN: {field} #URL: {url} added for more checking')
                            for_more_check_urls.add(url)
                        else:
                            # modified_html = re.sub(re.escape(original_url), url, modified_html)
                            logger.info(f'Skipped ID: {id} #COLUMN: {field} #URL: {url} #STATUS_CODE: {result.get("status_code")}')
                    continue
            
                updates.append(True)
                modified_html = re.sub(re.escape(url), ' ', modified_html)
                logger.info(f'ID: {id} #COLUMN: {field} #URL: {url if url else ("null")} #STATUS_CODE: {result.get("status_code")} - Replaced with #TEXT: (null)')
                
            if len(url_startwith_www) > 0:
                for result in do_http_request(urls=['https://{}'.format(url) for url in url_startwith_www], logger=logger, id=id):
                    url = result.get('url')
                    original_url = url[8:]
                    # original_url = f"http://{url[8:]}"
                    if not result.get('is_broken', False):
                        updates.append(True)
                        if result.get('status_code') in STATUS_CODES_FOR_FURTHER_CHECK:
                            modified_html = re.sub(re.escape(original_url), '', modified_html)
                            logger.info(f'ID: {id} #COLUMN: {field} #URL: {original_url if original_url else ("null")} #STATUS_CODE: {result.get("status_code")} - Replaced with #TEXT: (null)')
                        else:
                            modified_html = re.sub(re.escape(original_url), url, modified_html)
                            logger.info(f'ID: {id} #COLUMN: {field} #URL: {original_url if original_url else ("null")} #STATUS_CODE: {result.get("status_code")} - Replaced with: {url}')
                        continue
                
                    updates.append(True)
                    modified_html = re.sub(re.escape(url), ' ', modified_html)
                    logger.info(f'ID: {id} #COLUMN: {field} #URL: {url if url else ("null")} #STATUS_CODE: {result.get("status_code")} - Replaced with #TEXT: (null)')

        
    
        return modified_html, any(updates), for_more_check_urls
    except Exception as e:
        logger.exception(e)
        raise e
            
def do_remove_url(record: Dict[str, Any], logger: Logger, base_url: str):
    id = record.get('id')
    introtext = record.get('introtext')
    adjusted_introtext, need_update_introtext, intro_timeout_urls = extract_a_tag_in_html(
        logger=logger,
        id=id,
        field='introtext',
        html=introtext,
        base_url=base_url
    )

    fulltext = record.get('fulltext')
    adjusted_fulltext, need_update_fulltext, full_timeout_urls = extract_a_tag_in_html(
        logger=logger,
        id=id,
        field='fulltext',
        html=fulltext,
        base_url=base_url
    )
    if adjusted_introtext is None and adjusted_fulltext is None:
        logger.info(f'Skipped ID: {id} - Not found any URLs in both introtext, fulltext fields')
        return None, None, any([need_update_introtext, need_update_fulltext]), None
    
    return (
        adjusted_introtext if adjusted_introtext else introtext,
        adjusted_fulltext if adjusted_fulltext else fulltext,
        any([need_update_introtext, need_update_fulltext]),
        intro_timeout_urls.union(full_timeout_urls)
    )

def main(commit: bool = False, id: Optional[int] = 0):
    config = configparser.ConfigParser(interpolation=None)
    config.read(os.path.join(os.path.dirname(__file__), 'config.ini'))

    log_file = config.get('script-01', 'log_file')
    store_state_file = config.get('script-01', 'store_state_file')
    timeout_file = config.get('script-01', 'timeout_file')
    
    limit: int = config['script-01'].getint('limit')
    base_url: str = config.get('script-01', 'base_url')

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
        logger.error(e)
        raise e


    with connection.cursor() as cursor:
        sql = 'SELECT count(c.id) as total FROM xu5gc_content c LEFT JOIN xu5gc_categories cat ON cat.id = c.catid WHERE c.state = 1 AND cat.published = 1'
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
                sql = 'SELECT c.id, c.introtext, c.fulltext FROM xu5gc_content AS c LEFT JOIN xu5gc_categories cat ON cat.id = c.catid WHERE c.state = 1 AND cat.published = 1 AND c.id < %s ORDER BY  c.id DESC LIMIT %s'
                args = (current_id, limit)
            elif id > 0:
                sql = "SELECT c.id, c.introtext, c.fulltext FROM xu5gc_content AS c WHERE id =%s"
                args = (id)
            else:
                sql = 'SELECT c.id, c.introtext, c.fulltext FROM xu5gc_content AS c LEFT JOIN xu5gc_categories cat ON cat.id = c.catid WHERE c.state = 1 AND cat.published = 1 ORDER BY c.id DESC LIMIT %s'
                args = (limit)

            with connection.cursor() as cursor:
                cursor.execute(sql, args)
                result = cursor.fetchall()
            
            if len(result) == 0:
                logger.info(f'{"="*20} All records have been processed {"="*20}')
                break

            for record in result:
                counter += 1
                try:
                    logger.info(f'{"*"*20} Processing ID: {record.get("id")} {"*"*20} ({counter}/{total} - {percentage(counter, total)})')
                    introtext, fulltext, is_update, timeout_urls = do_remove_url(
                        record=record,
                        logger=logger,
                        base_url=base_url
                    )
                    if timeout_urls and len(timeout_urls) > 0:
                        write_file(filename=timeout_file, id=record.get("id"), urls=timeout_urls)

                    if is_update is False:
                        continue

                    if commit:
                        succeed = do_update(
                            connection=connection,
                            logger=logger,
                            id=record.get('id'),
                            introtext=introtext,
                            fulltext=fulltext
                        )
                        if succeed:
                            logger.info(f'ID: {record.get("id")} has been updated in database')
                    
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
            current_id = latest.get('id')
    
            if commit and id == 0:
                # write current running state to file if commit is True
                current_state(store_state_file, id=current_id, counter=counter, mode='w')
        except KeyboardInterrupt:
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
    
