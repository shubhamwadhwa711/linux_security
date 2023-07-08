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

HTTP_REQUEST_TIMEOUT = 10
FTP_REQUEST_TIMEOUT = 10

# Skiped Cloudflare status 403
# Skiped Amazon status 503
VALID_HTTP_STATUS_CODES = [403, 503]
STATUS_CODES_FOR_FURTHER_CHECK = ['Timeout', 'SSLError', 'ConnectionError']
VALID_FTP_STATUS_CODES = []

# Skiped twitter, facebook
SKIP_CHECK_SITES = ['twitter.com', 'facebook.com', 'linkedin.com']
SITE_WITH_GET_METHOD = ['portswigger.net']

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


def timeit(method):
    @wraps(method)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = method(*args, **kwargs)
        end_time = time.time()
        print(f"{method.__name__} => {(end_time-start_time)*1000} ms")

        return result

    return wrapper


def check_http_broken_link(url, timeout: int = HTTP_REQUEST_TIMEOUT):
    """Http status code

        1xx - informational
        2xx - success
        3xx - redirection
        4xx - client error
        5xx - server error
    """

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
        return response
    return response



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