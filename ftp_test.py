from ftplib import FTP
from urllib.parse import urlparse

def is_ftp_url_working(url):
    try:
        # Parse the URL
        parsed_url = urlparse(url)

        # Check if the scheme is 'ftp'
        if parsed_url.scheme != 'ftp':
            return False

        with FTP(parsed_url.netloc) as ftp:
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
        print(f"Error: {e}")
        return False

def check_ftp_broken_link(url, timeout: int = 10):
    ftp_urls = url.replace("ftp://","").split("/")
        
    host_url = ""
    main_path = ""

    for single_path in ftp_urls:
        if host_url == "":
            host_url = single_path
        else:
            main_path = main_path + "/" + single_path
    print("FTP_Host_URL",host_url)
    ftp = FTP(host_url, timeout=timeout)
    ftp.login()
    resp = ftp.sendcmd(f'MDTM {main_path}')
    ftp.quit()
    print("response",resp)
    return True

# Test the function with the provided FTP URL
# url = "ftp://ftp.slackware.com/pub/slackware/slackware-9.1/patches/packages/kernel-source-2.4.23-noarch-2.tgz"
# url = "ftp://ftp.slackware.com/pub/slackware/slackware-9.1/patches/kernels/"
url = "ftp://ftp.suse.com/"


if is_ftp_url_working(url):
    print(f"The FTP URL {url} is working.")
else:
    print(f"The FTP URL {url} is not working.")
