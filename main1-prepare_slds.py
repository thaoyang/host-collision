import argparse
import asyncio
import os
import re
import threading
from asyncio import CancelledError
from queue import Queue
from urllib.parse import urlparse, unquote
import aiohttp
from loguru import logger
from tldextract import extract
from html import unescape
import time
from tqdm import tqdm
from utils import hostwhois
import signal,sys
import json

# Set timeout
# socket.setdefaulttimeout(20)

class ActiveHttp:
    def __init__(self, targetlst:list, svpath, dm_keywords):
        """
        Initialize ActiveHttp class for root domain discovery (Initial mode)

        :param targetlst: Initial target domains or URLs to search
        :param svpath: Save path
        :param dm_keywords: Whois information indicator list
        """

        """Initialize parameters"""
        assert isinstance(targetlst, list)
        assert dm_keywords is not None
        assert isinstance(dm_keywords, list)
        assert svpath is not None
        logger.info("ActiveHTTP For Rootname Detection...")

        self.queue = Queue()

        for i in range(len(targetlst)):
            target = targetlst[i]
            if not target.startswith(('http://', 'https://')):
                targetlst[i] = 'http://' + target

        if dm_keywords is None:
            dm_keywords = []
            for target in targetlst:
                dm_keywords.append(extract(target).domain)
        self.dm_keywords = dm_keywords

        self.extract_urls = []  # Record which URLs have been crawled
        self.extracted_dmnums = dict()  # Record the number of URLs for the same domain entering the next iteration; avoid too many URLs
        self.maxparallels = 1000  # Maximum number of concurrent HTTP coroutine requests
        self._value_lock = threading.Lock()

        """Initialize storage lists"""
        self.root_domains = []
        self.hostwhois_dmnums = dict()  # Record the number of hostwhois queries for a root_domain; avoid too many queries
        self.whoisNone_rdm = set()  # Record root domains without whois display; for these domains, only record this round's results, no iterative updates
        self.svpath = svpath
        self.Test = dict()
        self.sub_domains = []

        """Store user input in queue"""
        for full_url in targetlst:
            self.extract_urls.append(full_url)
            self.queue.put(full_url)
            extract_full_url_domain = extract(full_url)
            root_domain = extract_full_url_domain.domain + '.' + extract_full_url_domain.suffix
            if root_domain not in self.root_domains:
                self.root_domains.append(root_domain)
            self.sub_domains.append(extract_full_url_domain.fqdn)

        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/79.0.3945.130 Safari/537.36'}
        """Regular expressions"""
        link_pattern = r"""
            (?:"|')                               # Start newline delimiter
            (
                ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
                [^"'/]{1,}\.                        # Match a domainname (any character + dot)
                [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
                |
                ((?:/|\.\./|\./)                    # Start with /,../,./
                [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
                [^"'><,;|()]{1,})                   # Rest of the characters can't be
                |
                ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
                [a-zA-Z0-9_\-/]{1,}                 # Resource name
                \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
                (?:[\?|/][^"|']{0,}|))              # ? mark with parameters
                |
                ([a-zA-Z0-9_\-]{1,}                 # filename
                \.(?:php|asp|aspx|jsp|json|
                    action|html|js|txt|xml)             # . + extension
                (?:\?[^"|']{0,}|))                  # ? mark with parameters
            )
            (?:"|')                               # End newline delimiter
		"""
        self.link_pattern = re.compile(link_pattern, re.VERBOSE)
        self.js_pattern = 'src=["\'](.*?)["\']'
        self.href_pattern = 'href=["\'](.*?)["\']'

        """Output passed Target and dm_keywords"""
        logger.info('[+]#Target ==> {}'.format(len(targetlst)))
        logger.info('[+]dm_keywords ==> {}'.format(self.dm_keywords))

    def signal_handler(self, signum, frame):
        """
        Custom signal handler function
        """
        self.initial_sv()
        # Exit program
        sys.exit(0)


    def initial_sv(self):
        now_time = str(int(time.time()))
        with open(self.svpath + self.dm_keywords[0] + '_' + now_time + '_subdomain', 'a+',
                  encoding='utf-8') as f:
            for sub_domain in self.sub_domains:
                f.write(sub_domain.strip() + '\n')
        with open(self.svpath + self.dm_keywords[0] + '_' + now_time + '_rootdomain', 'a+', encoding='utf-8') as f:
            f.write('Whois secret:\n')
            for root_domain in self.whoisNone_rdm:
                f.write(root_domain.strip() + '\n')
            f.write('\n')
            f.write('Whois right:\n')
            for root_domain in self.root_domains:
                if root_domain not in self.whoisNone_rdm:
                    f.write(root_domain.strip() + '\n')

        logger.info('[+]Root domains ==> {}'.format(self.svpath + self.dm_keywords[0] + '_' + now_time + '_rootdomain'))
        logger.info('[+]Sub domains ==> {}'.format(self.svpath + self.dm_keywords[0] + '_' + now_time + '_subdomain'))

        with open(self.svpath + self.dm_keywords[0] + '_' + now_time + '_rootdomain.json', 'w', encoding='utf-8') as f:
            json.dump(self.Test, f, ensure_ascii=False, indent=4)

        print("Data has been written to output.json file")


    def start(self):
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)  # Support Ctrl+C
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        pbar = tqdm(total=0)
        while not self.queue.empty():
            pbar.total = len(self.extract_urls)
            pbar.refresh()
            try:
                tasks = []
                i = 0
                while i < self.maxparallels and not self.queue.empty():
                    """Get basic information"""
                    url = self.queue.get()
                    """Create async task list based on file extension"""
                    filename = os.path.basename(url)
                    file_extend = self.get_file_extend(filename)
                    if file_extend == 'js':
                        tasks.append(asyncio.ensure_future(self.FindLinkInJs(url)))
                    else:
                        tasks.append(asyncio.ensure_future(self.FindLinkInPage(url)))
                    i += 1
                pbar.update(i)
                """Start running async tasks"""
                if tasks:
                    loop.run_until_complete(asyncio.wait(tasks))
                logger.info('-' * 20)

                logger.info('[+]sub domain count ==> {}'.format(len(self.sub_domains)))
                logger.info('[+]root domain count ==> {}'.format(len(self.root_domains)))
                logger.info('-' * 20)
            except KeyboardInterrupt:
                logger.info('[+]Break From Queue.')
                break
            # except CancelledError:
            #     pass
            except Exception as e:
                logger.info('[+]Error in ActiveHTTP!' + ' ' + str(e))


        logger.info('[+]All sub domain count ==> {}'.format(len(self.sub_domains)))
        logger.info('[+]All root domain count ==> {}'.format(len(self.root_domains)))

        self.initial_sv()

        logger.info("ActiveHTTP Module Ends Successfully.")

    async def FindLinkInPage(self, url):
        """Send request"""
        try:
            resp = await self.send_request(url)
        except ConnectionResetError:
            return None
        if not resp:
            return None
        """Extract href and js_urls from page"""
        try:
            hrefs = re.findall(self.href_pattern, resp)
        except TypeError:
            hrefs = []
        try:
            js_urls = re.findall(self.js_pattern, resp)
        except TypeError:
            js_urls = []
        try:
            js_texts = re.findall('<script>(.*?)</script>', resp)
        except TypeError:
            js_texts = []

        """Get complete URL"""
        for href in hrefs:
            self.extract_link(url, href)
        for js_url in js_urls:
            self.extract_link(url, js_url)
        for js_text in js_texts:
            self.FindLinkInJsText(url, js_text)

    async def FindLinkInJs(self, url):
        resp = await self.send_request(url)
        if not resp:
            return False
        try:
            link_finder_matchs = re.finditer(self.link_pattern, str(resp))
        except:
            return None
        for match in link_finder_matchs:
            match = match.group().strip('"').strip("'")
            self.extract_link(url, match)

    def FindLinkInJsText(self, url, text):
        try:
            link_finder_matchs = re.finditer(self.link_pattern, str(text))
        except:
            return None
        for match in link_finder_matchs:
            match = match.group().strip('"').strip("'")
            self.extract_link(url, match)

    async def send_request(self, url):
        """In this function, implement HTTP access for a URL and return document content"""
        """Fix asyncio historical bug"""
        sem = asyncio.Semaphore(1024)
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                async with sem:
                    async with session.get(url, timeout=20, headers=self.headers) as req:
                        await asyncio.sleep(1)
                        response = await req.text('utf-8', 'ignore')
                        req.close()
                        return response
        except CancelledError:
            pass
        except ConnectionResetError:
            pass
        except Exception as e:
            logger.warning('[-]Resolve {} fail:'.format(url))
            logger.warning(e)
            return False

    def get_file_extend(self, filename):
        return filename.split('/')[-1].split('?')[0].split('.')[-1].lower()

    def get_format_url(self, full_url):
        full_url = unquote(full_url)
        if "??" in full_url:
            full_url = full_url.replace("??", "")
            full_url = full_url.split(',')[0]

        parse_link = urlparse(full_url)
        filename = os.path.basename(full_url)

        format_filename = re.sub(r'\d+', 'x', filename)

        return parse_link.scheme + '://' + parse_link.netloc + parse_link.path.replace(filename, format_filename)

    def extract_link(self, ini_url, link):
        """HTML decode"""
        parse_url = urlparse(ini_url)
        link = unescape(link)
        """Check if extension is in blacklist"""
        filename = os.path.basename(link)
        file_extend = self.get_file_extend(filename)
        if link.startswith(('http://', 'https://')):
            full_url = link
        elif link.startswith('javascript:'):
            return
        elif link.startswith('////') and len(link) > 4:
            full_url = 'http://' + link[2:]
        elif link.startswith('//') and len(link) > 2:
            full_url = 'http:' + link
        elif link.startswith('/'):
            full_url = parse_url.scheme + '://' + parse_url.netloc + link
        elif link.startswith('./'):
            full_url = parse_url.scheme + '://' + parse_url.netloc + parse_url.path + link[1:]
        else:
            full_url = parse_url.scheme + '://' + parse_url.netloc + parse_url.path + '/' + link
        """Parse domain and root domain from crawled link"""
        extract_full_url_domain = extract(full_url)
        root_domain = extract_full_url_domain.domain + '.' + extract_full_url_domain.suffix
        sub_domain = extract_full_url_domain.fqdn
        """Check if crawled link satisfies keyword - need to compare with whois"""
        in_keyword = False
        host_whois_check = True
        try:
            self._value_lock.acquire()
            if root_domain in self.root_domains:
                in_keyword = True  # If root domain exists, it means this domain belongs to the tested service provider
                host_whois_check = False  # Already determined to belong to tested service provider, no need for another hostwhois request
            else:
                if root_domain in self.hostwhois_dmnums:  # For other root domains, need to perform hostwhois query to determine if this root domain should be included
                    if self.hostwhois_dmnums[root_domain] > 10:  # Maximum 10 hostwhois requests to ensure accuracy
                        host_whois_check = False
                    else:
                        self.hostwhois_dmnums[root_domain] += 1
                else:
                    self.hostwhois_dmnums[root_domain] = 1

        finally:
            self._value_lock.release()

        if host_whois_check:
            hostReginfo = hostwhois(root_domain)
            if hostReginfo == 'ERROR':
                # Whois query failed, skip
                return
            for keyword in self.dm_keywords:
                if keyword.lower() in hostReginfo.lower():
                    in_keyword = True
                    break
            # Check if privacy protection information is included (system whois may use different formats)
            if not in_keyword and ('REDACTED FOR PRIVACY' in hostReginfo or 'Privacy Protection' in hostReginfo or 'Whois Privacy' in hostReginfo):
                self.whoisNone_rdm.add(root_domain)

        if not in_keyword:
            if root_domain not in self.whoisNone_rdm:
                return

        """Add root domain"""
        try:
            self._value_lock.acquire()
            if root_domain not in self.root_domains:
                self.root_domains.append(root_domain)
                logger.info('[+]Find a new root domain ==> {} \tFull Url:{}\tSrc:{}'.format(root_domain, full_url, ini_url))
                self.Test[root_domain] = {"Full Url":full_url, "Src":ini_url}
            if root_domain not in self.whoisNone_rdm:  # For domains without whois records, only record root domain and subdomain once, no iterative queries
                url = 'http://' + root_domain
                if url not in self.extract_urls:
                    self.extract_urls.append(url)
                    self.queue.put(url)
        finally:
            self._value_lock.release()

        """Add subdomain"""
        try:
            self._value_lock.acquire()
            if sub_domain not in self.sub_domains and sub_domain != root_domain:
                self.sub_domains.append(sub_domain)
                logger.info('[+]Find a new subdomain ==> {}'.format(sub_domain))
                if root_domain not in self.whoisNone_rdm:  # For domains without whois records, only record root domain and subdomain once, no iterative queries
                    url = 'http://' + sub_domain
                    if url not in self.extract_urls:
                        self.extract_urls.append(url)
                        self.queue.put(url)
        finally:
            self._value_lock.release()

        format_url = self.get_format_url(full_url)  # When URLs with only changing numeric parts appear, set numbers to int, remove ?, # and other fields to avoid duplicates

        # Handle URLs with many duplicate domains, stop recording after more than 50
        if sub_domain not in self.extracted_dmnums:
            self.extracted_dmnums[sub_domain] = 1
        else:
            self.extracted_dmnums[sub_domain] += 1

        if self.extracted_dmnums[sub_domain] > 50:
            return

        # Finally, for URLs with specific paths, or URLs under https protocol (previously all under http protocol) - record separately (content is js or html)
        if file_extend != "js" and file_extend != "html":
            return
        if root_domain in self.whoisNone_rdm:  # For domains without whois, no longer enter iterative queries
            return
        try:
            self._value_lock.acquire()
            if format_url not in self.extract_urls:
                self.extract_urls.append(format_url)
                self.queue.put(full_url)
        finally:
            self._value_lock.release()

def main():
    """Main function: read parameters from config file and run ActiveHttp"""
    from config_loader import get_main1_config
    
    try:
        # Read parameters from config file
        config = get_main1_config()
        targetlst = config.get("targetlst", [])
        svpath = config.get("svpath", "")
        dm_keywords = config.get("dm_keywords", [])
        
        # Validate configuration
        if not targetlst:
            logger.error("targetlst in config file is empty, please check config.json")
            return
        if not svpath:
            logger.error("svpath in config file is empty, please check config.json")
            return
        if not dm_keywords:
            logger.error("dm_keywords in config file is empty, please check config.json")
            return
        
        # Ensure save path ends with /
        if not svpath.endswith('/'):
            svpath += '/'
        
        # Ensure save path exists
        os.makedirs(svpath, exist_ok=True)
        
        logger.info("=" * 50)
        logger.info("Read parameters from config file:")
        logger.info(f"  targetlst: {targetlst}")
        logger.info(f"  svpath: {svpath}")
        logger.info(f"  dm_keywords: {dm_keywords}")
        logger.info("=" * 50)
        
        # Create ActiveHttp instance and run
        scanner = ActiveHttp(
            targetlst=targetlst,
            svpath=svpath,
            dm_keywords=dm_keywords
        )
        
        scanner.start()
        
    except FileNotFoundError as e:
        logger.error(f"Config file does not exist: {e}")
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
    except Exception as e:
        logger.error(f"Runtime error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()