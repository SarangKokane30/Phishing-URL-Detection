import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date
from urllib.parse import urlparse

class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.domain = ""
        self.whois_response = None
        self.urlparse = None
        self.response = None
        self.soup = None
        self.features = []

        # Parse URL
        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            self.domain = ""

        # Get WHOIS information
        try:
            self.whois_response = whois.whois(self.domain)
        except:
            self.whois_response = None

        # Get page content
        try:
            self.response = requests.get(url, timeout=5)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            self.response = None
            self.soup = None

        # Extract all features
        self.features = [
            self.UsingIp(),
            self.longUrl(),
            self.shortUrl(),
            self.symbol(),
            self.redirecting(),
            self.prefixSuffix(),
            self.SubDomains(),
            self.Https(),
            self.DomainRegLen(),
            self.Favicon(),
            self.NonStdPort(),
            self.HTTPSDomainURL(),
            self.RequestURL(),
            self.AnchorURL(),
            self.LinksInScriptTags(),
            self.ServerFormHandler(),
            self.InfoEmail(),
            self.AbnormalURL(),
            self.WebsiteForwarding(),
            self.StatusBarCust(),
            self.DisableRightClick(),
            self.UsingPopupWindow(),
            self.IframeRedirection(),
            self.AgeofDomain(),
            self.DNSRecording(),
            self.WebsiteTraffic(),
            self.PageRank(),
            self.GoogleIndex(),
            self.LinksPointingToPage(),
            self.StatsReport()
        ]

    # 1. UsingIp
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    # 2. longUrl
    def longUrl(self):
        if len(self.url) < 54:
            return 1
        elif 54 <= len(self.url) <= 75:
            return 0
        else:
            return -1

    # 3. shortUrl
    def shortUrl(self):
        short_domains = (
            'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
            'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
            'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
            'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
            'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
            'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
            'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net'
        )
        if re.search(short_domains, self.url):
            return -1
        return 1

    # 4. Symbol @
    def symbol(self):
        return -1 if "@" in self.url else 1

    # 5. Redirecting //
    def redirecting(self):
        return -1 if self.url.rfind('//') > 6 else 1

    # 6. prefixSuffix
    def prefixSuffix(self):
        return -1 if '-' in self.domain else 1

    # 7. SubDomains
    def SubDomains(self):
        dots = self.url.count('.')
        if dots == 1:
            return 1
        elif dots == 2:
            return 0
        else:
            return -1

    # 8. HTTPS
    def Https(self):
        return 1 if self.urlparse and self.urlparse.scheme == 'https' else -1

    # 9. DomainRegLen
    def DomainRegLen(self):
        try:
            exp_date = self.whois_response.expiration_date
            create_date = self.whois_response.creation_date

            if isinstance(exp_date, list):
                exp_date = exp_date[0]
            if isinstance(create_date, list):
                create_date = create_date[0]

            months = (exp_date.year - create_date.year) * 12 + (exp_date.month - create_date.month)
            return 1 if months >= 12 else -1
        except:
            return -1

    # 10. Favicon
    def Favicon(self):
        try:
            if not self.soup:
                return -1
            for link in self.soup.find_all('link', href=True):
                dots = link['href'].count('.')
                if self.url in link['href'] or dots == 1 or self.domain in link['href']:
                    return 1
            return -1
        except:
            return -1

    # 11. NonStdPort
    def NonStdPort(self):
        return -1 if ':' in self.domain else 1

    # 12. HTTPSDomainURL
    def HTTPSDomainURL(self):
        return -1 if 'https' in self.domain else 1

    # 13. RequestURL
    def RequestURL(self):
        try:
            if not self.soup:
                return -1
            tags = ['img', 'audio', 'embed', 'iframe']
            i = success = 0
            for tag in tags:
                for element in self.soup.find_all(tag, src=True):
                    dots = element['src'].count('.')
                    if self.url in element['src'] or self.domain in element['src'] or dots == 1:
                        success += 1
                    i += 1
            perc = (success / i * 100) if i > 0 else 0
            if perc < 22:
                return 1
            elif perc < 61:
                return 0
            else:
                return -1
        except:
            return -1

    # 14. AnchorURL
    def AnchorURL(self):
        try:
            if not self.soup:
                return -1
            i = unsafe = 0
            for a in self.soup.find_all('a', href=True):
                href = a['href'].lower()
                if "#" in href or "javascript" in href or "mailto" in href or (self.url not in href and self.domain not in href):
                    unsafe += 1
                i += 1
            perc = (unsafe / i * 100) if i > 0 else 0
            if perc < 31:
                return 1
            elif perc < 67:
                return 0
            else:
                return -1
        except:
            return -1

    # 15. LinksInScriptTags
    def LinksInScriptTags(self):
        try:
            if not self.soup:
                return -1
            i = success = 0
            for tag in ['link', 'script']:
                for el in self.soup.find_all(tag, href=True) if tag=='link' else self.soup.find_all(tag, src=True):
                    dots = el['href'].count('.') if tag=='link' else el['src'].count('.')
                    if self.url in (el['href'] if tag=='link' else el['src']) or self.domain in (el['href'] if tag=='link' else el['src']) or dots == 1:
                        success += 1
                    i += 1
            perc = (success / i * 100) if i > 0 else 0
            if perc < 17:
                return 1
            elif perc < 81:
                return 0
            else:
                return -1
        except:
            return -1

    # 16. ServerFormHandler
    def ServerFormHandler(self):
        try:
            if not self.soup:
                return -1
            forms = self.soup.find_all('form', action=True)
            if len(forms) == 0:
                return 1
            for form in forms:
                action = form['action']
                if action == "" or action == "about:blank":
                    return -1
                elif self.url not in action and self.domain not in action:
                    return 0
            return 1
        except:
            return -1

    # 17. InfoEmail
    def InfoEmail(self):
        try:
            return -1 if self.soup and re.search(r"mailto:", str(self.soup)) else 1
        except:
            return -1

    # 18. AbnormalURL
    def AbnormalURL(self):
        try:
            if self.response and str(self.response.text) == str(self.whois_response):
                return 1
            return -1
        except:
            return -1

    # 19. WebsiteForwarding
    def WebsiteForwarding(self):
        try:
            if not self.response:
                return -1
            if len(self.response.history) <= 1:
                return 1
            elif len(self.response.history) <= 4:
                return 0
            else:
                return -1
        except:
            return -1

    # 20. StatusBarCust
    def StatusBarCust(self):
        try:
            if self.response and re.search(r"<script>.+onmouseover.+</script>", self.response.text):
                return 1
            else:
                return -1
        except:
            return -1

    # 21. DisableRightClick
    def DisableRightClick(self):
        try:
            return 1 if self.response and re.search(r"event.button ?== ?2", self.response.text) else -1
        except:
            return -1

    # 22. UsingPopupWindow
    def UsingPopupWindow(self):
        try:
            return 1 if self.response and re.search(r"alert\(", self.response.text) else -1
        except:
            return -1

    # 23. IframeRedirection
    def IframeRedirection(self):
        try:
            return 1 if self.response and re.search(r"<iframe>|<frameBorder>", self.response.text) else -1
        except:
            return -1

    # 24. AgeofDomain
    def AgeofDomain(self):
        try:
            create_date = self.whois_response.creation_date
            if isinstance(create_date, list):
                create_date = create_date[0]
            today = date.today()
            months = (today.year - create_date.year) * 12 + (today.month - create_date.month)
            return 1 if months >= 6 else -1
        except:
            return -1

    # 25. DNSRecording
    def DNSRecording(self):
        return self.AgeofDomain()  # same as age check

    # 26. WebsiteTraffic
    def WebsiteTraffic(self):
        try:
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + self.url).read(), "xml").find("REACH")['RANK']
            return 1 if int(rank) < 100000 else 0
        except:
            return -1

    # 27. PageRank
    def PageRank(self):
        try:
            prank_response = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain})
            global_rank = int(re.search(r"Global Rank: ([0-9]+)", prank_response.text)[1])
            return 1 if 0 < global_rank < 100000 else -1
        except:
            return -1

    # 28. GoogleIndex
    def GoogleIndex(self):
        try:
            return 1 if list(search(self.url, 5)) else -1
        except:
            return 1

    # 29. LinksPointingToPage
    def LinksPointingToPage(self):
        try:
            num_links = self.response.text.count('<a href=') if self.response else 0
            if num_links == 0:
                return 1
            elif num_links <= 2:
                return 0
            else:
                return -1
        except:
            return -1

    # 30. StatsReport
    def StatsReport(self):
        try:
            url_match = re.search(r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', self.url)
            ip_address = socket.gethostbyname(self.domain)
            ip_match = re.search(r'146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116', ip_address)
            if url_match or ip_match:
                return -1
            return 1
        except:
            return 1

    # Return features list
    def getFeaturesList(self):
        return self.features
