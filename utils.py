import os
import json
import time
from functools import wraps
import logging
import requests
from ftplib import FTP
from copy import copy
import configparser
from pathlib import Path
from typing import Tuple, Optional
from requests.exceptions import ConnectionError, ReadTimeout
from urllib import robotparser
from urllib.parse import urlparse
from urllib.request import urlopen
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service
import asyncio
import aiohttp
import csv
import contextlib
# from webdriver_manager.firefox import GeckoDriverManager
import requests
# from requests.packages.urllib3.exceptions import InsecureRequestWarning

# # Suppress the InsecureRequestWarning
# requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
config = configparser.ConfigParser(interpolation=None)
config.read(os.path.join(os.path.dirname(__file__), "config.ini"))
gecodriver_path = config.get('script-01', 'gecodriver_path')
gecodriver_required = eval(config.get('script-01', 'gecodriver_required'))

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
# SITE_WITH_GET_METHOD = ['portswigger.net', 'www.amd.com']
FTP_DECOMPOSE_URLS=['security.debian.org','ftp.redhat.com','download.fedora.redhat.com','updates.redhat.com','fedora.redhat.com','listserv.fnal.gov','kbase.redhat.com']


import json

# Load the configuration file
with open('config.json', 'r') as config_file:
    config_data = json.load(config_file)

SITE_WITH_GET_METHOD = config_data['SITE_WITH_GET_METHOD']





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
    
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "time": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": json.loads(record.getMessage())
        }
        return json.dumps(log_record)
    
def get_logger(name, log_file, level=logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    file = logging.FileHandler(log_file)  
    json_formatter = JsonFormatter()      
    file.setFormatter(json_formatter)
    logger.addHandler(file)

    console = logging.StreamHandler()
    console.setFormatter(ColoredFormatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(console)
    return logger


@contextlib.contextmanager
def create_webdriver(options, gecodriver_required=False, gecodriver_path=None):
    if not gecodriver_required:
        driver = webdriver.Firefox(options=options)
    else:
        service = Service(executable_path=gecodriver_path)
        driver = webdriver.Firefox(options=options, service=service)
    try:
        yield driver
    finally:
        driver.quit()


async def check_url_with_selenium(url, logger, gecodriver_required=False, gecodriver_path=None):
    options = FirefoxOptions()
    options.add_argument("--headless")
    def check_url():
        with create_webdriver(options, gecodriver_required, gecodriver_path) as driver:
            try:
                driver.get(url)
                if "Error" in driver.title or "Not Found" in driver.title or "Page not found" in driver.title:
                    return {'url': url, 'status_code': 404, 'is_error': True, "is_redirect": False}
                return {'url': url, 'status_code': 200, 'is_error': False, "is_redirect": False}
            except Exception as e:
                logger.error(f'Error checking URL {url}: {repr(e)}')
                return {'url': url, 'status_code': 500, 'is_error': True, "is_redirect": False}    
    return await asyncio.get_event_loop().run_in_executor(None, check_url)    



def selenium_check(url,response,logger):
    try:
        options=FirefoxOptions()
        options.add_argument("--headless")
        if not gecodriver_required:
            driver=webdriver.Firefox(options=options)
        else:
            service=Service(executable_path=gecodriver_path)
            driver=webdriver.Firefox(options=options,service=service)
        driver.get(url)
        if "Error" in driver.title or "Not Found" in driver.title:     
            driver.quit()
            return {'url':url,'status_code':404,'is_error':True,"is_redirect":False}
        response.status_code=200
        driver.quit()
        return {'url':url,'status_code':200,'is_error':False,"is_redirect":False}
    except Exception as e:
        driver.quit()
        return {'url':url,'status_code':500,'is_error':True,"is_redirect":False}


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
        return result

    return wrapper


async  def new_check_http_broken_link(url, session:aiohttp.ClientSession, logger,id,timeout: int = HTTP_REQUEST_TIMEOUT):
    headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"}
    try:
        if any(site in url for site in SITE_WITH_GET_METHOD):
            async with session.get(url, headers=headers, timeout=timeout) as response:
                if response.status == 404:
                    return await check_url_with_selenium(url=url,logger=logger)
                return {'url':url,'status_code':response.status,'is_error':False,"is_redirect":False}
        else:
            async with session.head(url, headers=headers, timeout=timeout) as response:
                if response.status == 404:
                    return await check_url_with_selenium(url=url,logger=logger)
                if response.status in [405, 403, 301, 302]:
                    async with session.get(url,headers=headers, timeout=timeout) as response:
                        return {'url':url, "redirect_url":str(response.url),"is_redirect":True,'is_error':False,"status_code":response.status}
                return {'url':url,'status_code':response.status,'is_error':False,"is_redirect":False}
    except Exception as e:
        return {'url':url,'status_code':{'type':type(e) ,'message':str(e)},'is_error':True,"is_redirect":False}
        
    

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
            return {'url':url,'status_code':response.status_code,'is_error':False,"is_redirect":False}
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
            return {'url':url,'status_code':response.status_code,'is_error':False,"is_redirect":False}

    except (ReadTimeout, ConnectionError) as e:
        logger.warning(json.dumps({'ID': id, 'URL': url ,'Error': str(e)}))
        logger.info(json.dumps({'#ID': id, 'URL' :url,"action" : "Requesting again using GET request instead of HEAD"}))
        response = requests.get(
            url=url,
            headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"},
            timeout=timeout,verify=False
        )
        return {'url':url,'status_code':response.status_code,'is_error':False,"is_redirect":False}


def check_broken_url(url, timeout):
    """
    check url type
    if ftp:
        return check_ftp_broken_link
    return check_http_brokien_link
    
    """

# def check_ftp_broken_link(url, timeout: int = FTP_REQUEST_TIMEOUT):
#     ftp_urls = url.replace("ftp://","").split("/")
        
#     host_url = ""
#     main_path = ""

#     for single_path in ftp_urls:
#         if host_url == "":
#             host_url = single_path
#         else:
#             main_path = main_path + "/" + single_path
#     print("FTP_Host_URL",host_url)
#     ftp = FTP(host_url, timeout=timeout)
#     print(ftp.login())
#     ftp.login()
#     resp = ftp.sendcmd(f'MDTM {main_path}')
#     ftp.quit()
#     print("response",resp)
#     return resp

def check_ftp_broken_link(url,logger, timeout: int = FTP_REQUEST_TIMEOUT):
    try:
        # Parse the URL
        parsed_url = urlparse(url)

        # Check if the scheme is 'ftp'
        if parsed_url.scheme != 'ftp':
            return False

        with FTP(parsed_url.netloc, timeout=timeout) as ftp:
            # Login anonymously or provide credentials if needed
            ftp.login()

            # Extract the directory and file name
            path_parts = parsed_url.path.strip('/').split('/')
            dir_path = '/'.join(path_parts[:-1])  # Directory path
            file_name = path_parts[-1]  # File name

            # Change the current working directory to the directory containing the file
            if dir_path:
                ftp.cwd(dir_path)

            if not file_name:
                return True
            # Check if the file exists
            file_exists = file_name in ftp.nlst()

            return file_exists

    except Exception as e:
        logger.error(json.dumps({"ERROR":f"Error while checking FTP url {url}: {e}"}))
        return False


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

def write_img_urls(filename:str,id,urls:Optional[Tuple[str]]=None):
    if urls is None:
        return
    try:
        with open(filename,mode='r',newline='') as file:
            reader=csv.reader(file)
            existing_data=list(reader)
    except FileNotFoundError:
        existing_data=[]

    existing_data.extend([[id, url] for url in urls])
    with open(filename,mode='w',newline='') as file:
        writer=csv.writer(file)
        writer.writerows(existing_data)



def write_redirect_urls(filename:str,data:dict):
    try:
        with open(filename,'r') as file:
           file_data = json.load(file)
    except FileNotFoundError:
        file_data = []

    file_data.append(data)
    with open(filename,'w') as f:
        json.dump(file_data,f,indent=4)



def concatenate_log_files(nested_log_files,log_file):
    consolidated_data=[]
    for i in nested_log_files:
        with open(i, "r") as individual_log:
            try:
                file_data = json.load(individual_log)
                if isinstance(file_data, list):
                    consolidated_data.extend(file_data)
                else:
                    consolidated_data.append(file_data)
            except json.JSONDecodeError:
                individual_log.seek(0)  # Go back to the start of the file
                for line in individual_log:
                    if line.strip():
                        consolidated_data.append(json.loads(line.strip()))
            os.remove(i)   
    with open(log_file, "w") as consolidated_log:
        json.dump(consolidated_data, consolidated_log, indent=4)



def concatenate_img_csv_files(nested_imgcsv_files,img_file):
    all_img_data=[]
    for i in nested_imgcsv_files:
        if os.path.exists(i):
            with open(i,'r',newline='') as file:
                reader=csv.reader(file)
                all_img_data.extend(row for row in reader)
                os.remove(i)
    with open(img_file, 'w', newline='') as outfile:
        writer = csv.writer(outfile)
        writer.writerows(all_img_data)


def concatenate_timeout_files(nested_timeout_files,timeout_file):
    merged_data={}
    for i in nested_timeout_files:
        if os.path.exists(i):
            with open(i, "r") as json_file:
                data = json.load(json_file)  
                merged_data.update(data)
                os.remove(i)
    with open(timeout_file,"w") as final_timeout_urls:
        json.dump(merged_data,final_timeout_urls,indent=4)


def concatenate_redirected_urls_file(redirect_urls_files,redirected_file):
    merged_data=[]
    for i in redirect_urls_files:
        if os.path.exists(i):
            with open(i, "r") as json_file:
                data = json.load(json_file)  
                merged_data.extend(data)
                os.remove(i)
    with open(redirected_file,"w") as final_redirect_file:
        json.dump(merged_data,final_redirect_file,indent=4)



def write_generic_modified_url_file(filename:str,data:dict):
    try:
        with open(filename,'r') as file:
           file_data = json.load(file)
    except FileNotFoundError:
        file_data = []

    file_data.append(data)
    with open(filename,'w') as f:
        json.dump(file_data,f,indent=4)


def concatenate_generic_modfiled_url_file(generic_nested_url_file,generic_file):
    merged_data=[]
    for i in generic_nested_url_file:
        if os.path.exists(i):
            with open(i, "r") as json_file:
                data = json.load(json_file)  
                merged_data.extend(data)
                os.remove(i)
    with open(generic_file,"w") as final_redirect_file:
        json.dump(merged_data,final_redirect_file,indent=4)
