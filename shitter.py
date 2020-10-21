#!/usr/bin/env python3

import re
from os import chdir
from os.path import dirname
from pprint import pprint
from random import randrange, sample as randsample
from sys import argv, exit
from time import sleep
from uuid import uuid4

from requests import Session
from requests.exceptions import HTTPError, ProxyError


class RandomInt:
    """Random number in range"""
    def __init__(self, low, high):
        self.low = low
        self.high = high

    def __str__(self):
        return str(randrange(self.low, self.high + 1))


class RandomChoice(list):
    """Random value out of a list"""
    def get(self):
        return str(self[randrange(len(self))])

    def __str__(self):
        return self.get()


class RandomEmail:
    """Ditto"""
    def __init__(self, domains):
        self.domains = domains

    def get(self):
        user = str(uuid4()).replace('-', '')[:12]
        return "%s@%s" % (user, self.domains)

    def __str__(self):
        return self.get()


class RandomImage(RandomChoice):
    """Random image file for a multipart form"""
    def get(self):
        s = super().get()
        return (s, open(s, 'rb'), 'image/jpeg', {})


class ScrambledString:
    """Russian letters are sometimes replaced with similar-looking English ones"""
    MAPPING = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x'
    }

    def __init__(self, initial):
        self.initial = initial

    def __str__(self):
        ret = '%s' % self.initial
        return ''.join([self.MAPPING[c] if c in self.MAPPING and randrange(0, 10) > 5 else c for c in ret])


class UserBannedException(Exception):
    pass


class UserRemovedException(Exception):
    pass


class StartOverException(Exception):
    pass


# You need a proxy in Russia or Ukraine to register. Any proxy will do for spamming.
PROXIES = {
    'RO1': {'host': '95.174.67.50', 'port': 18080},
    'RO2': {'host': '83.97.23.90', 'port': 18080},
    'RU8': {'host': '79.111.13.155 ', 'port': 50625},
    'RU7': {'host': '178.215.76.193', 'port': 53281},
    'KH1': {'host': '103.216.51.210', 'port': 8191},
    'RU3': {'host': '195.9.188.78', 'port': 53281},
    'JP1': {'host': '182.23.211.110', 'port': 80},
    'US5': {'host':  '20.44.193.208', 'port': 80},
    'CZ1': {'host': '81.201.60.130', 'port': 80},  # tor?
    'FR1': {'host': '51.38.71.101', 'port': 8080},  # does not work with mailnesia: sfs listed
    'FR2': {'host': '178.33.251.230', 'port': 3129},  # does not work with mailnesia: sfs listed
    'US4': {'host': '34.92.94.5', 'port': 8123},
    'RU1': {'host': '188.120.232.181', 'port': 8118}
}
POST_DELAY = 0
PASSWORD = '[eq1gbplf2'
PROFILE = {
    'start': {
        'email': RandomEmail(RandomChoice(['mail.ru', 'gala.net', 'yandex.ru', 'gmail.com'])),
        'password': PASSWORD,
        'name': ScrambledString(RandomChoice(['Администрация', 'Детектор сучек', 'Детектор фейков'])),
        'countryId': '[192]',  # Украина - 231, Россия - 192
        'cityId': '[17451]',  # Одесса - 19991, Сызрань - 17451
        'genderId': RandomInt(1, 9),
        'ad': RandomChoice([
            'Обнаружение и маркировка вредоносных аккаунтов',
        ]),
        'isPublic': '1'
    }, 'fetish': {
        'positionId': ''
    }, 'goals': {
        'about': '',
        'taboo': ''
    }, 'photo': {
        'storageIdent': 'null'
    }
}
# userpics. files must be located in the same folder with the script (or path must be specified)
IMAGES = RandomImage(['alco.jpeg'])
EMAIL_HOST = 'mailnesia.com'

RETRY_ATTEMPTS = 5
RETRY_INITIAL_DELAY = 1
RETRY_INCREMENT = 1

# more or less good people that we don't want to bother with PMs
SKIP_LIST = (
    1260,  # Ева (Зефирка)
    3118,  # Зоряна
    10764,  # Lex_Amorph
    10834,  # Пани Ольга
    13907,  # Людмила
    14663,  # Shamistic
    16501,  # KinkyAngel
    16748,  # Sadness
    17900,  # Gella Noir
    18857,  # Бегемот
)


def retry(func, attempts=RETRY_ATTEMPTS, initial_delay=RETRY_INITIAL_DELAY, increment=RETRY_INCREMENT):
    attempts_made = 0
    delay = initial_delay
    while True:
        try:
            ret = func()
            break
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print('Error %s: %s, retrying…' % (type(e).__name__, e))
            attempts_made += 1
            if attempts_made == attempts:
                raise
            sleep(delay)
            delay += increment
    return ret


class ProxyChecker:
    """Proxies controller with dead hosts elimination and rechecking"""
    WTFIP_URL = 'https://wtfismyip.com/json'
    IFME_URL = 'http://ifconfig.me/ip'

    def __init__(self, proxies, recheck_interval=60, max_retries=2):
        self.proxies = list(proxies.values())
        self.session = Session()
        self.recheck_interval = recheck_interval
        self.max_retries = max_retries

    def get_ip_by_wtfismyip(self):
        response = retry(lambda: self.session.get(self.WTFIP_URL), attempts=self.max_retries)
        content_type = response.headers.get('Content-Type', '').split(';')[0]
        if content_type != 'application/json':
            print('failed! wrong content type: %s' % content_type)
            raise ProxyError('Wrong response format')
        return response.json().get('YourFuckingIPAddress')

    def get_ip_by_ifconfig(self):
        response = retry(lambda: self.session.get(self.IFME_URL), attempts=self.max_retries)
        if not response.ok:
            print('failed!')
            raise ProxyError('ifconfig.me error')
        return response.content.decode('utf-8').strip()

    def check_proxy(self, proxy_set, host):
        print('Checking proxy cloaking for %s... ' % proxy_set['https'], end='', flush=True)
        self.session.proxies = proxy_set
        real_ip = self.get_ip_by_ifconfig()
        print('reported IP is %s. ' % real_ip, end='')
        ok = real_ip == host
        if not ok:
            print('failed! (expected=%s, received=%s)' % (host, real_ip))
            raise ProxyError('Proxy isn''t anonymous')
        print('success!')

    def get(self):
        while True:
            proxies = randsample(self.proxies, len(self.proxies))
            for proxy in proxies:
                host_port = 'http://%s:%d' % (proxy['host'], proxy['port'])
                proxy_set = {'http': host_port, 'https': host_port}
                try:
                    self.check_proxy(proxy_set, proxy.get('out_host', proxy['host']))
                    return proxy_set
                except ProxyError:
                    pass
            print('No proxies online, sleeping for %d seconds...' % self.recheck_interval, flush=True)
            sleep(self.recheck_interval)


class Mailnesia:
    """Mailnesia confirmation mail grabber"""
    MN_BASE = 'http://' + EMAIL_HOST + '/'
    MAIL_RE = re.compile(r'onClick="openEmail\(\'[0-9a-f]+\',(\d+)\)')
    CODE_RE = re.compile(r'(https://fetside.com/\w+/email-confirmation/new\?key=[a-f0-9]+)')

    def __init__(self, email, proxy_checker, proxy_set=None, recheck_interval=5, max_checks=20):
        self.email = email.split('@')[0]
        self.proxy_checker = proxy_checker
        self.recheck_interval = recheck_interval
        self.max_checks = max_checks
        self.session = Session()
        #  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        #  self.session.proxies = proxy_set or proxy_checker.get()
        self.session.proxies = {
            'http': 'socks5://localhost:9150',
            'https': 'socks5://localhost:9150'
        }
        #  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        self.session.headers = {
            'Accept': 'text/css,*/*;q=0.1',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Cookie': 'language=en; mailbox=%s' % self.email,
            'Host': EMAIL_HOST,
            'Referer': 'https://' + EMAIL_HOST,
            'User-Agent': 'Mozilla/5.0 (Windows; rv:73.0) Gecko/20100101 Firefox/73.0',
        }

    def list_emails(self):
        print('Listing emails... ', end='', flush=True)
        if 'X-Requested-With' in self.session.headers:
            self.session.headers.pop('X-Requested-With')
        url = self.MN_BASE + ('mailbox/%s' % self.email)
        response = retry(lambda: self.session.get(url))
        if not response.ok:
            raise HTTPError('Listing emails failed: %r' % response)
        ids = self.MAIL_RE.findall(response.content.decode('utf-8'))
        print('done.')
        return [int(id) for id in ids]

    def scan_email(self, id):
        print('Scanning email %d... ' % id, end='', flush=True)
        self.session.headers['X-Requested-With'] = 'XMLHttpRequest'
        url = self.MN_BASE + ('mailbox/%s/%d?noheadernofooter=ajax' % (self.email, id))
        response = retry(lambda: self.session.get(url))
        if not response.ok:
            raise HTTPError('Listing emails failed')
        match = self.CODE_RE.search(response.content.decode('utf-8'))
        return match.group(1) if match else None

    def get_code(self):
        print('Waiting for the confirmation code...')
        ok = False
        i = 0
        while not ok:
            sleep(self.recheck_interval)
            try:
                email_ids = self.list_emails()
                for email_id in email_ids:
                    code = self.scan_email(email_id)
                    if code:
                        print('Received confirmation code: %s' % code)
                        return code
            except ProxyError:
                self.session.headers = self.proxy_list.get()
            except HTTPError as e:
                print('failed: %s' % e)
            i += 1
            if i == self.max_checks:
                raise UserRemovedException('No confirmation email!')


class Fetside:
    """Main code goes here"""
    FETSIDE_BASE = 'https://fetside.com/ru/'
    CSRF_RE = re.compile(r'csrf=([0-9a-f]{8})')
    USER_RE = re.compile(r'id(\d+)$')
    ACTIVITY_RE = re.compile(r'/\w{2}/id(\d+)/activity')
    POST_LINK_RE = re.compile(r'<a class="user-post-li__link reversed".*?href="/\w+/post/(\d+)">', flags=re.DOTALL)
    ALBUM_PHOTO_LINK_RE = re.compile(r'data-url="&#x2F;\w+&#x2F;photo&#x2F;(\d+)&', flags=re.DOTALL)
    PROFILE_PHOTO_LINK_RE = re.compile(r'<a.*?data-url="/\w+/photo/(\d+)">', flags=re.DOTALL)
    PM_HTML_LINK_RE = re.compile(r'\w{2}&#x2F;id\d+&#x2F;message&#x2F;add&#x3F;toUserId&#x3D;(\d+)', flags=re.DOTALL)
    PM_JSON_LINK_RE = re.compile(r'toUserId\\u0026#x3D;(\d+)\\u0022', flags=re.DOTALL)

    def __init__(self, target_id, payload_filename, rounds, profile, images, proxy_checker, post_delay=0):
        self.target_id = int(target_id)
        with open(payload_filename, 'rt') as f:
            self.payload = "\n".join(f.readlines())
        self.rounds = int(rounds)
        self.profile = profile
        self.images = images
        self.proxy_checker = proxy_checker
        self.post_delay = post_delay

        self.session = Session()
        self.session.proxies = self.proxy_checker.get()
        self.session.headers = {
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9,ru;q=0.8,sm;q=0.7',
            'Host': 'fetside.com',
            'Origin': 'https://fetside.com',
            'Referer': self.FETSIDE_BASE,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0',
            'X-Requested-With': 'XMLHttpRequest',
        }
        self.csrf_token = None
        self.email = None

    @staticmethod
    def check_response(resp, json_wanted=True, ignore404=False):
        if not resp.ok and (resp.status_code != 404 or not ignore404):
            raise StartOverException('query failed with code %d' % resp.status_code)
        content_type = resp.headers.get('Content-Type', '').split(';')[0]
        if json_wanted:
            if content_type != 'application/json':
                raise StartOverException('json expected but %s received' % content_type)
            for msg in resp.json().get('flashMessenger', []):
                if msg.get('type') == 'error':
                    raise UserBannedException('error: %s' % msg.get('message'))
        else:
            if content_type != 'text/html':
                raise StartOverException('html expected but %s received' % content_type)

    @staticmethod
    def make_choice(data):
        return {k: str(v) for k, v in data.items()}

    def mode(self, m):
        if m == 'json':
            self.session.headers['X-Requested-With'] = 'XMLHttpRequest'
        elif m == 'html':
            if 'X-Requested-With' in self.session.headers:
                self.session.headers.pop('X-Requested-With')
        else:
            raise Exception('Unknown mode %s' % m)

    def login(self, email, password):
        print('Logging in... ', end='', flush=True)
        self.mode('json')
        login_data = {
            'email': email,
            'password': password,
            'shouldNotStay': '0',
        }
        url = self.FETSIDE_BASE + 'log-in'
        response = retry(lambda: self.session.post(url, data=login_data))
        self.check_response(response)
        print('success!')

    def obtain_csrf_token(self, url=None):
        print('Obtaining CSRF token... ', end='', flush=True)
        self.mode('html')
        if url is None:
            url = self.FETSIDE_BASE + 'blogs'
        response = retry(lambda: self.session.get(url))
        self.check_response(response, json_wanted=False)
        page_src = response.content.decode('utf-8')
        match = self.CSRF_RE.search(page_src)
        if not match:
            raise UserRemovedException('cannot obtain CSRF token')
        self.csrf_token = match.group(1)
        match = self.ACTIVITY_RE.search(page_src)
        if not match:
            raise UserRemovedException('cannot obtain user id')
        self.user_id = int(match.group(1))
        print('token=%s, my user id=%d' % (self.csrf_token, self.user_id))

    def reg_start(self):
        print('Starting registration... ', end='', flush=True)
        self.mode('json')
        self.session.cookies.clear()
        url = self.FETSIDE_BASE + 'registration'
        data = self.make_choice(self.profile['start'])
        response = retry(lambda: self.session.post(url, data=data))
        self.check_response(response)
        redir = response.json().get('redirect', '') or ''
        if not redir.endswith('fetish'):
            raise StartOverException('no redirection to the next page')
        self.email = data['email']
        print('success!')

    def reg_fetish(self):
        print('Updating fetishes... ', end='', flush=True)
        self.mode('json')
        url = self.FETSIDE_BASE + 'registration/fetish'
        data = self.make_choice(self.profile['fetish'])
        response = retry(lambda: self.session.post(url, data=data))
        self.check_response(response)
        redir = response.json().get('redirect', '') or ''
        if not redir.endswith('goals'):
            raise StartOverException('no redirection to the next page')
        print('success!')

    def reg_goals(self):
        print('Updating goals... ', end='', flush=True)
        self.mode('json')
        url = self.FETSIDE_BASE + 'registration/goals'
        data = self.make_choice(self.profile['goals'])
        response = retry(lambda: self.session.post(url, data=data))
        self.check_response(response)
        redir = response.json().get('redirect', '') or ''
        match = self.USER_RE.search(redir)
        if not match:
            raise StartOverException('no redirection to the next page')
        self.user_id = int(match.group(1))
        print('success!')

    def reg_photo(self):
        print('Uploading photo... ', end='', flush=True)
        self.mode('json')
        url = self.FETSIDE_BASE + ('id%d/settings/upload-main-user-photo' % self.user_id)
        data = self.make_choice(self.profile['photo'])
        files = {'image': self.images.get()}
        response = retry(lambda: self.session.post(url, data=data, files=files))
        self.check_response(response)
        if not len(response.json().get('htmlList', [])):
            raise StartOverException('No response for the image upload')
        print('success!')

    def reg_email(self):
        print('Changing email... ', end='', flush=True)
        self.mode('json')
        self.email = RandomEmail('mailnesia.com').get()
        url = self.FETSIDE_BASE + ('id%d/settings/change-email' % self.user_id)
        email_data = {
            'csrf': self.csrf_token,
            'email': self.email,
            'shouldAddBigWaterMark': '0',
            'isPublic': 0
        }
        response = retry(lambda: self.session.post(url, data=email_data))
        self.check_response(response)
        print('success! new email address is %s' % self.email)

    def reg_confirm_email(self):
        self.mode('html')
        mailnesia = Mailnesia(self.email, self.proxy_checker, self.session.proxies)
        url = mailnesia.get_code()
        response = retry(lambda: self.session.get(url))
        self.check_response(response, json_wanted=False)
        print('Email address confirmed!')

    def register(self, confirm=True):
        ok = False
        while not ok:
            try:
                self.reg_start()
                self.reg_fetish()
                self.reg_goals()
                self.reg_photo()
                if confirm:
                    self.obtain_csrf_token()
                    self.reg_email()
                    self.reg_confirm_email()
                ok = True
            except (StartOverException, UserRemovedException, UserBannedException):
                pass
            except ProxyError:
                self.session.proxies = self.proxy_checker.get()
        url = self.FETSIDE_BASE + ('id%d' % self.user_id)
        print('Registered new user, login: %s, url: %s' % (self.email, url))

    def list_posts(self, pages=10000):
        print('Getting posts list... ', end='', flush=True)
        self.mode('html')
        i = 1
        post_ids = []
        while True:
            print('page %d... ' % i, end='', flush=True)
            url = self.FETSIDE_BASE + ('id%d/index/user-post?page=%d' % (self.target_id, i))
            response = retry(lambda: self.session.get(url))
            self.check_response(response, json_wanted=False)
            ids = self.POST_LINK_RE.findall(response.content.decode('utf-8'))
            ids = [int(id) for id in ids]
            post_ids.extend(ids)
            if len(ids) < 10:
                break
            i += 1
            if i > pages:
                break
        self.post_ids = list(set(post_ids))
        print('%d posts found.' % len(self.post_ids))

    def list_album_photos(self):
        print('Listing album photos... ', end='', flush=True)
        self.mode('html')
        url = self.FETSIDE_BASE + ('id%d/albums/photos?albumId=-1' % self.target_id)
        response = retry(lambda: self.session.get(url))
        self.check_response(response, json_wanted=False)
        ids = self.ALBUM_PHOTO_LINK_RE.findall(response.content.decode('utf-8'))
        return [int(id) for id in ids]

    def list_profile_photos(self):
        print('listing profile photos... ', end='', flush=True)
        self.mode('html')
        url = self.FETSIDE_BASE + ('id%d' % self.target_id)
        response = retry(lambda: self.session.get(url))
        self.check_response(response, json_wanted=False)
        ids = self.PROFILE_PHOTO_LINK_RE.findall(response.content.decode('utf-8'))
        return [int(id) for id in ids]

    def list_photos(self):
        all_photos = sorted(self.list_album_photos() + self.list_profile_photos())
        self.photo_ids = [id for i, id in enumerate(all_photos) if not i or id != all_photos[i - 1]]
        print('%d photos found.' % len(self.photo_ids))

    def list_users(self, path, print_result=False):
        print('Listing users for path %s... ' % path, flush=True, end='')
        user_ids = []
        print('starting page... ', flush=True, end='')
        self.mode('html')
        url = self.FETSIDE_BASE + ('id%d/community?path=%s' % (self.user_id, path))
        response = retry(lambda: self.session.get(url))
        self.check_response(response, json_wanted=False)
        ids = self.PM_HTML_LINK_RE.findall(response.content.decode('utf-8'))
        user_ids.extend(ids)
        start = 12
        self.mode('json')
        while len(ids) == 12:
            print('offset %d... ' % start, flush=True, end='')
            url = self.FETSIDE_BASE + ('id%d/community/load-more?start=%d' % (self.user_id, start))
            response = retry(lambda: self.session.get(url))
            self.check_response(response)
            ids = self.PM_JSON_LINK_RE.findall(response.content.decode('utf-8'))
            user_ids.extend(ids)
            start += 12
        if print_result:
            pprint(user_ids, compact=True)
        print('%d users found.' % len(user_ids))
        return [int(uid) for uid in user_ids]

    def send_message(self, recipient_id, text, fetcoins=0):
        url = self.FETSIDE_BASE + ('id%d' % recipient_id)
        self.obtain_csrf_token(url)
        self.mode('json')
        print('Sending message to id %d... ' % recipient_id, flush=True, end='')
        url = self.FETSIDE_BASE + ('id%d/message/add?toUserId=%d' % (self.user_id, recipient_id))
        message_data = {
            'csrf': self.csrf_token,
            'photoList[]': '',
            'text': text,
            'shouldAddFriend': '0',
            'diamondCount': fetcoins,
        }
        response = retry(lambda: self.session.post(url, data=message_data))
        self.check_response(response)
        print('success!')

    def defecate(self):
        self.obtain_csrf_token(self.FETSIDE_BASE + ('id%d' % self.target_id))
        for i in range(self.rounds):
            for where, label, ids in (
                (self.FETSIDE_BASE + 'post/%d/add-comment', 'post', self.post_ids),
                (self.FETSIDE_BASE + 'photo/%d/add-comment', 'photo', self.photo_ids),
            ):
                for id in ids:
                    print('Defecating to %s #%d, round %d/%d' % (label, id, i + 1, self.rounds))
                    try:
                        comment_data = {
                            'text': self.payload,
                            'csrf': self.csrf_token,
                        }
                        url = where % id
                        self.mode('json')
                        response = retry(lambda: self.session.post(url, data=comment_data))
                        self.check_response(response, ignore404=True)
                        if self.post_delay:
                            sleep(self.post_delay)
                    except ProxyError:
                        self.session.proxies = self.proxy_checker.get()
                    except UserRemovedException as e:
                        print('!!! User removed: %s' % e)
                        exit(1)
                        self.register()
                        self.list_posts()
                        self.list_photos()
                    except UserBannedException as e:
                        print('!!! Banned: %s' % e)
                        exit(1)
                        self.register()
                        self.list_posts()
                        self.list_photos()
                    except StartOverException as e:
                        print('Error: %s' % e)  # TODO подробнее, если будет повторяться.
                        exit(1)

    def spam(self, recipient_ids, text):
        for recipient_id in recipient_ids:
            if recipient_id in SKIP_LIST:
                print('Skipping id %d' % recipient_id)
                continue
            try:
                self.send_message(recipient_id, text)
            except ProxyError:
                self.session.proxies = self.proxy_checker.get()
            except UserRemovedException as e:
                print('!!! User removed: %s' % e)
                exit(1)
            except UserBannedException as e:
                print('!!! Failed to send to %d: %s' % (recipient_id, e))

    def run_defecate(self):
        #  self.register()
        self.login('YOUR.EMAIL@yandex.ru', PASSWORD)
        self.list_posts(pages=1)
        self.list_photos()
        self.defecate()

    def run_register(self):
        for i in range(self.rounds):
            print('Registering account %d/%d' % (i + 1, self.rounds))
            self.register(confirm=False)

    def run_spam(self):
        self.login('YOUR.EMAIL@yandex.ru', PASSWORD)
        self.obtain_csrf_token()
        recipient_ids = sorted(self.list_users('0.1231'))
        self.spam(recipient_ids, self.payload)

    def run_transfer(self, recipient_id=None):
        if recipient_id is None:
            recipient_id = self.target_id
        else:
            recipient_id = int(recipient_id)
        logins = (
            'c1e8b695dfef@gala.net',
            '416e538c75c0@gmail.com',
            '6ad5b1789f3c@yandex.ru',
            '3fd5e05e16ec@mail.ru',
            'a9ee818436d4@mail.ru',
        )
        for login in logins:
            self.session.cookies.clear()
            self.login(login, PASSWORD)
            print('Transferring 3 fecal coins to %d...' % recipient_id, flush=True)
            self.send_message(recipient_id, 'Дань!', 3)


def make_shitter(target_id, payload_filename, proxy_checker, rounds):
    return Fetside(
        target_id=target_id, payload_filename=payload_filename, rounds=rounds, profile=PROFILE, images=IMAGES,
        proxy_checker=proxy_checker, post_delay=POST_DELAY
    )


if __name__ == '__main__':
    if len(argv) != 4:
        print('Usage: %s user_id message_file rounds' % argv[0])
        exit(0)
    try:
        chdir(dirname(argv[0]))
    except FileNotFoundError:
        pass
    shitter = make_shitter(
        target_id=argv[1], payload_filename=argv[2], rounds=argv[3], proxy_checker=ProxyChecker(PROXIES))
    shitter.run_defecate()
