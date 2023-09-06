import os
import json
import time
from functools import wraps
import logging
import requests
from ftplib import FTP
from copy import copy
from pathlib import Path
from typing import Tuple, Optional
from requests.exceptions import ConnectionError, ReadTimeout
from urllib import robotparser
from urllib.parse import urlparse
from urllib.request import urlopen
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
import asyncio
import aiohttp
from webdriver_manager.firefox import GeckoDriverManager

HTTP_REQUEST_TIMEOUT = 10
FTP_REQUEST_TIMEOUT = 5

# Skiped Cloudflare status 403
# Skiped Amazon status 503
VALID_HTTP_STATUS_CODES = [403, 503, 429]
STATUS_CODES_FOR_FURTHER_CHECK = ['Timeout', 'SSLError', 'ConnectionError',500]
VALID_FTP_STATUS_CODES = []

# Skiped twitter, facebook
SKIP_CHECK_SITES = ['twitter.com', 'facebook.com', 'linkedin.com','www.facebook.com','www.linkedin.com','www.twitter.com']
DECOMPOSE_URLS=['ftp.redhat.com', 'download.fedora.redhat.com', 'kbase.redhat.com', 'listserv.fnal.gov', 'fedora.redhat.com', 'updates.redhat.com', ]
# SITE_WITH_GET_METHOD = ['portswigger.net']
SITE_WITH_GET_METHOD = ['portswigger.net', 'www.amd.com']
FTP_DECOMPOSE_URLS=['security.debian.org','ftp.redhat.com','download.fedora.redhat.com','updates.redhat.com','fedora.redhat.com','listserv.fnal.gov','kbase.redhat.com']

formatter = logging.Formatter(
    fmt='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

MAPPING = {
    'DEBUG'   : 37, # white
    'INFO'    : 36, # cyan
    'WARNING' : 33, # yellow
    'ERROR'   : 31, # red
    'CRITICAL': 41, # white on red bg
}

PREFIX = '\033['
SUFFIX = '\033[0m'

class ColoredFormatter(logging.Formatter):
    datefmt = "%Y-%m-%d %H:%M:%S"

    def __init__(self, patern):
        logging.Formatter.__init__(self, patern)

    def format(self, record):
        colored_record = copy(record)
        levelname = colored_record.levelname
        seq = MAPPING.get(levelname, 37) # default white
        colored_levelname = ('{0}{1}m{2}{3}') \
            .format(PREFIX, seq, levelname, SUFFIX)
        colored_record.levelname = colored_levelname
        return logging.Formatter.format(self, colored_record)
    
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


async def new_selenium_check(url,response,logger):
    options = FirefoxOptions()
    options.add_argument("--headless")
    servi=Service(executable_path="/usr/local/bin/geckodriver")
    driver = webdriver.Firefox(service=servi,options=options)
    driver.get(url)
    search_texts = ["404", "not found", "page not found"]  # Add more search texts if needed
    for text in search_texts:
        if text.lower() in driver.page_source.lower():
            driver.quit()
            return {'url':url,'status_code':404,'is_error':True}
    response.status=200
    driver.quit()
    return {'url':url,'status_code':200,'is_error':False}


def selenium_check(url,response,logger):
    options = FirefoxOptions()  
    options.add_argument("--headless")
    service=Service(executable_path="/home/admin123/Downloads/geckodriver-v0.33.0-linux-aarch64")
    driver = webdriver.Firefox(service=service,options=options)
    # chrome_options = Options()
    # chrome_options.add_argument("--headless")
    # chrome_service = Service(executable_path="chromedriver")
    # driver = webdriver.Chrome(options=chrome_options, service=chrome_service)
    driver.get(url)
    search_texts = ["404", "not found", "page not found"]  # Add more search texts if needed
    for text in search_texts:
        if text.lower() in driver.page_source.lower():
            driver.quit()
            # if str(response.url) != url:
            #     logger.info(f"response url not match with original url set the original url with in place of response url ")
            #     st=response.url
            #     st=url
            #     response=st
            return response
    response.status_code=200
    driver.quit()
    return response


def check_url_against_domains(url):
    parsed_url = urlparse(url)
    if parsed_url.scheme in ['ftp','http','https']:
        domain = parsed_url.netloc
        domain=domain.lower()
        if any(domain.endswith(d) for d in DECOMPOSE_URLS):
            return True
    return False
  

 

def timeit(method):
    @wraps(method)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = method(*args, **kwargs)
        end_time = time.time()
        print(f"{method.__name__} => {(end_time-start_time)*1000} ms")

        return result

    return wrapper


async  def new_check_http_broken_link(url, session:aiohttp.ClientSession, logger,id,timeout: int = HTTP_REQUEST_TIMEOUT):
    try:
        if any(site in url for site in SITE_WITH_GET_METHOD):
            async with session.get(url, headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"}, timeout=timeout) as response:
                if response.status == 404:
                    return await new_selenium_check(url, response,logger)
                return {'url':url,'status_code':response.status,'is_error':False}
        else:
            async with session.head(url, headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"}, timeout=timeout) as response:
                if response.status in [405, 403, 301, 302]:
                    async with session.get(url, headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"}, timeout=timeout) as response:
                        pass  
                if response.status == 404:
                    return await new_selenium_check(url, response,logger)

                return {'url':url,'status_code':response.status,'is_error':False}
           
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logger.warning(f'#ID: {id} #URL {url} Error: {str(e)}')
        logger.info(f'#ID: {id} #URL {url} - Requesting again using GET request instead of HEAD')
        try:
            async with session.get(url, headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"}, timeout=timeout) as response:
                return {'url':url,'status_code':response.status,'is_error':False}
        except Exception as e:
            return {'url':url,'status_code':{'type':type(e) ,'message':str(e)},'is_error':True}
    except Exception as e:
        logger.warning(f'#ID: {id} #URL {url} Error: {str(e)}')
        return {'url':url,'status_code':{'type':type(e) ,'message':str(e)},'is_error':True}
        
    

def check_http_broken_link(url,logger, id, timeout: int = HTTP_REQUEST_TIMEOUT):
    """Http status code

        1xx - informational
        2xx - success
        3xx - redirection
        4xx - client error
        5xx - server error
    """
    try:
        if any(site in url for site in SITE_WITH_GET_METHOD):
            response = requests.get(
                url=url,
                headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"},
                timeout=timeout
            )
            if response.status_code==404:
                return selenium_check(url,response,logger)
            return response
        else:
            response = requests.head(
                url=url,
                headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"},
                timeout=timeout
            )
            if response.status_code  in [405,403, 301, 302] or any(site in url for site in SITE_WITH_GET_METHOD): # 405 Method Not Allowed - Try with GET instead
                response = requests.get(
                    url=url,
                    headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"},
                    timeout=timeout
                )
            if response.status_code==404:
                return selenium_check(url,response,logger)
            return response

    except (ReadTimeout, ConnectionError) as e:
        logger.warning(f'#ID: {id} #URL {url} Error: {str(e)}')
        logger.info(f'#ID: {id} #URL {url} - Requesting again using GET request instead of HEAD')
        response = requests.get(
            url=url,
            headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"},
            timeout=timeout
        )
        return response
    return response

def check_broken_url(url, timeout):
    """
    check url type
    if ftp:
        return check_ftp_broken_link
    return check_http_brokien_link
    
    """

def check_ftp_broken_link(url, timeout: int = FTP_REQUEST_TIMEOUT):
    ftp_urls = url.replace("ftp://","").split("/")
        
    host_url = ""
    main_path = ""

    for single_path in ftp_urls:
        if host_url == "":
            host_url = single_path
        else:
            main_path = main_path + "/" + single_path

    ftp = FTP(host_url, timeout=timeout)
    ftp.login()
    resp = ftp.sendcmd(f'MDTM {main_path}')
    ftp.quit()
    return resp


def current_state(index_filename: str, id: int = 0, counter: int = 0, mode='r'):
    filename = os.fspath(index_filename)
    baseFilename = os.path.abspath(filename)
    if os.path.exists(baseFilename) == False or mode == 'w':
        with open(index_filename, 'w') as f:
            json.dump({
                'id': id,
                'counter': counter
            }, f, indent=4)
        return id, counter
    else:
        with open(baseFilename, 'r') as f:
            data = json.load(f)
            return int(data.get('id')), int(data.get('counter'))


def percentage(number, total):
    per = float(number)/float(total)
    to_str = "{:.1%}".format(per)
    return to_str

def read_file(filename):
    # Create file if not exist
    fle = Path(filename)
    fle.touch(exist_ok=True)
    try:
        with open(fle, 'r') as f:
            data = json.load(f)
            return data
    except json.decoder.JSONDecodeError as e:
        return {}

def find_id(id, data):
    for key in data.keys():
        if int(key) == id:
            return data[key]
    else:
        return None
    
def write_file(filename: str, id, urls: Optional[Tuple[str]] = None):
    data = read_file(filename=filename)
    if urls and len(urls) > 0:
        data[str(id)] = list(urls)
    else:
        try:
            del data[str(id)]
        except:
            pass

    with open(filename, 'w') as f:
        str_ = json.dumps(data, indent=4)
        f.write(str_)