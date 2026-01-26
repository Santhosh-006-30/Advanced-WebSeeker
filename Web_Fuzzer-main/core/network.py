
import requests
import random
import time
import urllib3
from config import USER_AGENTS, TIMEOUT, DELAY, Colors

# Disable SSL warnings for cleaner output
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Network:
    def __init__(self):
        self.session = requests.Session()
        
        # Optimize connection pooling
        adapter = requests.adapters.HTTPAdapter(pool_connections=500, pool_maxsize=500)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        self.update_headers()
        # Global verification setting
        self.session.verify = False 

    def update_headers(self):
        self.session.headers.update({
            "User-Agent": random.choice(USER_AGENTS)
        })

    def get(self, url, params=None, **kwargs):
        self._delay()
        try:
            return self.session.get(url, params=params, timeout=TIMEOUT, verify=False, **kwargs)
        except requests.RequestException as e:
            # Colors.warning(f"Request failed: {url} - {e}")
            return None

    def post(self, url, data=None, json=None, **kwargs):
        self._delay()
        try:
            return self.session.post(url, data=data, json=json, timeout=TIMEOUT, verify=False, **kwargs)
        except requests.RequestException as e:
            # Colors.warning(f"Request failed: {url} - {e}")
            return None

    def _delay(self):
        if DELAY > 0:
            time.sleep(DELAY)

# Global singleton
requester = Network()
