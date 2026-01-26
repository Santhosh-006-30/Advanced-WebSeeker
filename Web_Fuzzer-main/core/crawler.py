
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from config import Colors

class Crawler:
    def __init__(self, target_url):
        self.target_url = target_url
        self.visited_urls = set()
        self.discovered_urls = []
        self.domain = urlparse(target_url).netloc

    def crawl(self, depth=2):
        """
        Crawls the target URL to discover endpoints.
        depth: integer (1 = just the page, 2 = one level deep, etc.)
        """
        Colors.info(f"Starting Crawler on {self.target_url} (Depth: {depth})...")
        self._crawl_recursive(self.target_url, depth)
        
        # Always ensure the base URL is in the list
        if self.target_url not in self.discovered_urls:
             self.discovered_urls.insert(0, self.target_url)
             
        Colors.success(f"Crawler finished. Found {len(self.discovered_urls)} unique endpoints.")
        return self.discovered_urls

    def _crawl_recursive(self, url, current_depth):
        if current_depth == 0 or url in self.visited_urls:
            return

        self.visited_urls.add(url)
        
        try:
            response = requests.get(url, timeout=5)
            if response.status_code != 200:
                return

            soup = BeautifulSoup(response.text, 'html.parser')
            
            # --- Extract Links (href) ---
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(url, href)
                parsed_url = urlparse(full_url)

                # Only crawl within the same domain
                if parsed_url.netloc == self.domain:
                    # Filter out static assets usually not interesting for fuzzing
                    if not any(full_url.endswith(ext) for ext in ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg']):
                        if full_url not in self.discovered_urls:
                            self.discovered_urls.append(full_url)
                            print(f"  [+] Discovered: {full_url}")
                        
                        # Recurse
                        self._crawl_recursive(full_url, current_depth - 1)
            
            # --- Extract Forms (action) ---
            for form in soup.find_all('form', action=True):
                action = form['action']
                full_url = urljoin(url, action)
                if full_url not in self.discovered_urls:
                    self.discovered_urls.append(full_url)
                    print(f"  [+] Form Action Found: {full_url}")

        except Exception as e:
            # Colors.warning(f"Error crawling {url}: {e}")
            pass
