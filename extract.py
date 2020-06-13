#!/usr/bin/python3
import re
import pandas as pd
import whois
from bs4 import BeautifulSoup
import requests
import timeout_decorator
import tldextract
import urllib.parse
import csv
from requests.exceptions import InvalidSchema
import socket
from datetime import datetime, time
import logging

import geoip2.database


ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
ipv6_pattern = r"^(?:(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){6})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):" \
               r"(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}" \
               r"(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:::(?:(?:(?:[0-9a-fA-F]{1,4})):){5})" \
               r"(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|" \
               r"(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|" \
               r"(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){4})" \
               r"(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|" \
               r"(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|" \
               r"(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,1}(?:(?:[0-9a-fA-F]{1,4})))?::" \
               r"(?:(?:(?:[0-9a-fA-F]{1,4})):){3})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|" \
               r"(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}" \
               r"(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,2}" \
               r"(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){2})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):" \
               r"(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|" \
               r"(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,3}" \
               r"(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:[0-9a-fA-F]{1,4})):)(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):" \
               r"(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}" \
               r"(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,4}" \
               r"(?:(?:[0-9a-fA-F]{1,4})))?::)(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|" \
               r"(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|" \
               r"(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,5}" \
               r"(?:(?:[0-9a-fA-F]{1,4})))?::)(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,6}" \
               r"(?:(?:[0-9a-fA-F]{1,4})))?::))))$"
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"
http_https = r"https://|http://"


phishing = {
    "ip"        : 2,
    "url length": 2,
    "tiny url"  : 2,
    "@ symbol"  : 2,
    "url redirection": 2,
    "hyphen"    : 2,
    "dots"      : 2,
    "unicode"   : 2,
    "http"      : 2,
    "domain"    : 2,
    "favicon"   : 2,
    "url domain": 2,
    "anchor"    : 2,
    "tag links" : 2,
    "iframe"    : 2,
    "js"        : 2
}

not_suspicious = {
    "ip"        : 0,
    "url length": 0,
    "tiny url"  : 0,
    "@ symbol"  : 0,
    "url redirection": 0,
    "hyphen"    : 0,
    "dots"      : 0,
    "unicode"   : 0,
    "domain"    : 0,
    "favicon"   : 0,
    "url domain": 0,
    "anchor"    : 0,
    "tag links" : 0,
    "iframe"    : 0,
    "js"        : 0
}

suspicious = {
    "url length": 1,
    "dots"      : 1,
    "http"      : 1,
    "anchor"    : 1,
    "tag links" : 1

}


# NumDots
def num_dots(url_path):
    if having_ip_address(url_path) == -1:
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5]))|(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',
            url_path)
        pos = match.end()
        url_path = url_path[pos:]
    num_dots = [x.start() for x in re.finditer(r'\.', url_path)]
    return len(num_dots)

# Subdomain levels
def num_subdomain(url_path):
    subdomain = tldextract.extract(url_path)
    return len(subdomain.subdomain.split("."))

# depth of a url
def num_levels_url(url_path):
    url_path = url_path.split("//")[-1]
    num_levels = [x.start() for x in re.finditer("/", url_path)]
    return len(num_levels)

# url length
def url_length(url_addr):
    return len(url_addr)

# number of -
def num_hyphens(url_path):
    num = [x.start() for x in re.finditer("-", url_path)]
    return len(num)

# number of - in hostname
def num_hyphens_hostname(url_path):
    hostname = tldextract.extract(url_path).fqdn
    num = [x.start() for x in re.finditer("-", hostname)]
    return len(num)

# ~ symbol
def num_tilde_symbol(url_addr):
    match = re.search('~', url_addr)
    return 1 if match else 0

# @ symbol
def num_at_symbol(url_addr):
    match = re.search("@", url_addr)
    return 1 if match else 0


# number of _ 
def num_underscores(url_path):
    num = [x.start() for x in re.finditer("_", url_path)]
    return len(num)

# number of % 
def num_percent(url_path):
    num = [x.start() for x in re.finditer("%", url_path)]
    return len(num)


# number of & 
def num_ampersand(url_path):
    num = [x.start() for x in re.finditer("&", url_path)]
    return len(num)


# number of # 
def num_hash_symbol(url_path):
    num = [x.start() for x in re.finditer("#", url_path)]
    return len(num)


# number of query parts
def num_query_parts(url_path):
    parse = urllib.parse.urlparse(url_path)
    return len(parse.query.split("&"))


# number of sensitive words
def num_sensitive_words(url_addr):
    sensitive_words = ["secure", "account", "webscr", "login", "ebayisapi", "signin", "banking", "confirm", "password"]
    num = 0
    for w in sensitive_words:
        num += len([x.start() for x in re.finditer(w,url_addr)])

    return num

# IP used as alternative to domain name
def having_ip_address(url_addr):
    ip_address_pattern = ipv4_pattern + "|" + ipv6_pattern
    match = re.search(ip_address_pattern, url_addr)
    return 1 if match else 0


# Long URL to Hide the Suspicious Part
# def url_length(url_addr):
#     if len(url_addr) < 54:
#         return not_suspicious["url length"]
#     if 54 <= len(url_addr) <= 75:
#         return phishing["url length"]
#     return suspicious["url length"]


# Using URL Shortening Services like bit.ly
def shortening_service(url_addr):
    match = re.search(shortening_services, url_addr)
    return phishing["tiny url"] if match else not_suspicious["tiny url"]


# @ will ignore everything preceding
def having_at_symbol(url_addr):
    match = re.search('@', url_addr)
    return phishing["@ symbol"] if match else not_suspicious["@ symbol"]


# // will redirect
def double_slash_redirecting(url_addr):
    last_double_slash = url_addr.rfind('//')
    # if pos after https:/
    return phishing["url redirection"] if last_double_slash > 6 else not_suspicious["url redirection"]

isascii = lambda s: len(s) == len(s.encode())
# unicode in url
def unicode_in_url(url_path):
    # if not url_path.isascii():
    if not isascii(url_path):
        return phishing["unicode"]
    return not_suspicious["unicode"]


# https and http
def https_token(url_addr):
    match = re.search(http_https, url_addr)
#     if match and match.start() == 0:
#         url_addr = url_addr[match.end():]
    match = re.search('https', url_addr)
    return suspicious["http"] if match else phishing["http"]


# domain should be in URL
def abnormal_url(domain, url_addr):
    hostname = domain
    match = re.search(hostname, url_addr)
    return phishing["url domain"] if match else phishing["url domain"]


def get_hostname_from_url(url):
    hostname = url
    pattern = "https://|http://|www.|https://www.|http://www."
    pre_pattern_match = re.search(pattern, hostname)

    if pre_pattern_match:
        hostname = hostname[pre_pattern_match.end():]
        post_pattern_match = re.search("/", hostname)
        if post_pattern_match:
            hostname = hostname[:post_pattern_match.start()]

    return hostname

# check if domain registration less than a year
def domain_registration_length(domain):
    expiration_date = domain.expiration_date
   
    registration_length = 0
    # Some domains do not have expiration dates
    if expiration_date:
        registration_length = abs(expiration_date - datetime.now()).days

    return phishing["domain"] if registration_length / 365 <= 1 else not_suspicious["domain"]


# Favicons loaded from external link can be a sign of phishing
def favicon(wiki, soup, domain):
  
    for head in soup.find_all('head'):
        for head.link in soup.find_all('link', href=True):
            dots = [x.start() for x in re.finditer(r'\.', head.link['href'])]
            return not_suspicious["favicon"] if wiki in head.link['href'] or len(dots) == 1 or domain in head.link[
                'href'] else phishing["favicon"]
    return not_suspicious["favicon"]


# Too many external links in <a> or does not link to any webpage/handled by javascript
def url_of_anchor(wiki, soup, domain):
    i = 0
    unsafe = 0
    for a in soup.find_all('a', href=True):
        if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (
                wiki in a['href'] or domain in a['href']):
            unsafe = unsafe + 1
        i = i + 1
        # print a['href']

    try:
        percentage = unsafe / float(i) * 100
    except Exception as e:
        return 0

    if percentage < 31.0:
        return not_suspicious["anchor"]
    elif 31.0 <= percentage < 67.0:
        return suspicious["anchor"]
    else:
        return phishing["anchor"]


# Links in <Script> and <Link> tags
def links_in_tags(wiki, soup, domain):
    i = 0
    success = 0
    for link in soup.find_all('link', href=True):
        dots = [x.start() for x in re.finditer(r'\.', link['href'])]
        if wiki in link['href'] or domain in link['href'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    for script in soup.find_all('script', src=True):
        dots = [x.start() for x in re.finditer(r'\.', script['src'])]
        if wiki in script['src'] or domain in script['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1
    try:
        percentage = success / float(i) * 100
    except:
        return not_suspicious["tag links"]

    if percentage < 17.0:
        return not_suspicious["tag links"]

    elif 17.0 <= percentage < 81.0:
        return suspicious["tag links"]
    else:
        return phishing["tag links"]


# IFrame Redirection
def i_frame(soup):
    for frame in soup.find_all('i_frame', width=True, height=True, frameBorder=True):
        if frame['width'] == "0" or frame['height'] == "0" or frame['frameBorder'] == "0":
            return phishing["iframe"]
    # If none of the iframes have a width or height of zero or a frameBorder of size 0, then it is safe to return 1.
    return not_suspicious["iframe"]


@timeout_decorator.timeout(60)
def check_suspicious_js(soup):
    script_list = []

    eval_regex = 'eval(?:\s+\w+)*\s*\(([^),]*)(\s*,\s*[^),]*){2,}\)'
    unescape_regex = 'unescape(?:\s+\w+)*\s*\(([^),]*)(\s*,\s*[^),]*){2,}\)'
    escape_regex = 'escape(?:\s+\w+)*\s*\(([^),]*)(\s*,\s*[^),]*){2,}\)'
    link_regex = 'link(?:\s+\w+)*\s*\(([^),]*)(\s*,\s*[^),]*){2,}\)'
    exec_regex = 'exec(?:\s+\w+)*\s*\(([^),]*)(\s*,\s*[^),]*){2,}\)'
    search_regex = 'search(?:\s+\w+)*\s*\(([^),]*)(\s*,\s*[^),]*){2,}\)'
    # create_regex = 'document.createElement\(\'script\'\)'
    # write_regex = 'document.write\(?:\s+\w+)*\s*\(([^),]*)(\s*,\s*[^),]*){2,}\)'

    for script in soup.find_all('script', src=False):
        if len(script.contents) > 0:  # and str(script.contents[0]):
            script_list.append(str(script.contents[0]))

    for script in soup.find_all('script', src=True):
        try:
            req = requests.get("http://" + script['src'].split("//")[1])
        except:
            req = -1

        # Content of external js
        if not req == -1:
            if req.content.decode("utf-8"):
                script_list.append(req.content.decode("utf-8"))

    results = {
        # 'result': type,
        'eval': 0,
        'escape': 0,
        'unescape': 0,
        'search': 0,
        'link': 0,
        'exec': 0,
        # 'write': 0,
        # 'create': 0
    }

    for script in script_list:
        eval_result = re.findall(eval_regex, script)
        escape_result = re.findall(escape_regex, script)
        unescape_result = re.findall(unescape_regex, script)
        search_result = re.findall(search_regex, script)
        link_result = re.findall(link_regex, script)
        exec_result = re.findall(exec_regex, script)
        # write_result = re.findall(write_regex, script)
        # create_result = re.findall(create_regex, script)

        results['eval'] += results['eval'] + len(eval_result)
        results['escape'] += results['escape'] + len(escape_result)
        results['unescape'] += results['unescape'] + len(unescape_result)
        results['search'] += results['search'] + len(search_result)
        results['link'] += results['link'] + len(link_result)
        results['exec'] += results['exec'] + len(exec_result)
        # results['write'] += results['write'] + len(write_result)
        # results['create'] += results['create'] + len(create_result)

    if results['eval'] > 1 or results['search']>0:
        return phishing['js']
    return not_suspicious['js']
    # return results



# check pop-ups
def check_popup_js(soup):
    script_list = []
    results = 0
    popup_regex = 'window\.open(?:\s+\w+)*\s*\(([^),]*)(\s*,\s*[^),]*){2,}\)'
    for script in soup.find_all('script', src=False):
        if len(script.contents) > 0:  # and str(script.contents[0]):
            script_list.append(str(script.contents[0]))

    for script in soup.find_all('script', src=True):
        try:
            req = requests.get("http://" + script['src'].split("//")[1])
        except:
            req = -1

        # Content of external js
        if not req == -1:
            if req.content.decode("utf-8"):
                script_list.append(req.content.decode("utf-8"))

    for script in script_list:
        popup_result = re.findall(popup_regex, script)
        results += len(popup_result)

    return results    


# domain
# autonomous system
def get_asn_org(reader_obj, url_addr):
    domain = tldextract.extract(url_addr).fqdn
    try:
        ip = socket.gethostbyname(domain)
        response = reader_obj.asn(ip)
        return response.autonomous_system_organization
    except:
        return "NA"

# country code
def get_domain_reg_country_code(reader_obj, url_addr):
    try:
        domain = tldextract.extract(url_addr).fqdn

        ip = socket.gethostbyname(domain)
        response = reader_obj.country(ip)
        return response.country.name
    except:
        return "NA"

label_ip_address = {}

asn_reader = geoip2.database.Reader('GeoLite2-ASN.mmdb')
country_reader = geoip2.database.Reader('GeoLite2-Country.mmdb')

@timeout_decorator.timeout(20)
def main(url, result):
    
    r = requests.get(url)
    soup = BeautifulSoup(r.content, 'html.parser')

    status = []
    hostname = get_hostname_from_url(url)

    status.append(url)
    #ip address in url
    status.append(having_ip_address(url))
    # numbere of dots
    status.append(num_dots(url))
    # number of subdomains
    status.append(num_subdomain(url))
    # number of urls
    status.append(num_levels_url(url))
    # length of urls
    status.append(url_length(url))
    # number of hyphens in entire url
    status.append(num_hyphens(url))
    # number of hyphens in hostname
    status.append(num_hyphens_hostname(url))
    # number of @ in url
    status.append(num_at_symbol(url))
    # number of ~ in url
    status.append(num_tilde_symbol(url))
    # number of & in url
    status.append(num_ampersand(url))
    # number of # in url
    status.append(num_hash_symbol(url))
    # number of query parts
    status.append(num_query_parts(url))
    # number of sensitive words
    status.append(num_sensitive_words(url))


    status.append(shortening_service(url))
    status.append(double_slash_redirecting(url))
    # status.append(having_sub_domain(url))
    status.append(unicode_in_url(url))

    # ASN
    status.append(get_asn_org(asn_reader, url))
    # Domain country
    status.append(get_domain_reg_country_code(country_reader, url))

    domain = tldextract.extract(url).fqdn
#    dns = 1
#    try:
#        domain = whois.query(hostname)
#    except Exception as err:
#        print(err)
#        dns = -1

    status.append(https_token(url))
#    status.append("DNS unsuccessful" if dns == -1 else domain_registration_length(domain))
    # status.append(age_of_domain(domain))
    status.append(favicon(url, soup, hostname))
#    if dns==1:
#        status.append(abnormal_url(domain.name, url))
#    else:
#        status.append(abnormal_url(domain, url))

    status.append(url_of_anchor(url, soup, hostname))
    status.append(links_in_tags(url, soup, hostname))
    status.append(i_frame(soup))
    status.append(check_suspicious_js(soup))
    status.append(check_popup_js(soup))
    status.append(result)
    return status



df_phishing = pd.read_json("https://raw.githubusercontent.com/ebubekirbbr/pdd/master/input/data_phishing_37175.json")
#df_legitimate = pd.read_json("https://raw.githubusercontent.com/ebubekirbbr/pdd/master/input/data_legitimate_36400.json")

#df_legitimate = df_legitimate
results = []

# Logging
logfile_name = "url_phishing_2.log"
logging.basicConfig(format='%(message)s',
                        datefmt='%Y-%m/%dT%H:%M:%S',
                        filename=logfile_name,
                        level=logging.INFO)
# Legit
'''for url in df_legitimate[0]:

    url_https = url
    if not url.startswith('http'):
        url = "http://" + url
        url_https = "https://" + url.split("//")[1]
    logging.info(url)

    try:
        results.append(main(url_https, "Legitimate"))
    except InvalidSchema as err:
        print(err, " in __main__ legitimate")
        results.append(main(url, "Legitimate"))
    except Exception as err:
        print(err, " in __main__ legitimate")
        

transactions = []
for row in results:
    transactions.append(tuple(map(str, row)))
'''
'''
with open("legit_features.tsv", 'w') as f:
#     for key in phishing.keys():
#         f.write(str(key) + ",")

    for _list in transactions:
        for _string in _list:
            f.write(str(_string) + "\t")

        f.write(str('\n'))

'''
# Phishing URLs

for url in df_phishing[0].tail(10000):
    url_https = url
    if not url.startswith('http'):
        url = "http://" + url
        url_https = "https://" + url.split("//")[1]

    #logging.info(url_https)
    try:
        x= main(url_https, "Phishing")
        logging.info(x)
        results.append(x)
    except InvalidSchema as err:
        print(err, " in __main__ phishing")
        results.append(main(url, "Phishing"))
    except Exception as err:
        print(err, " in __main__ phishing")


transactions = []
for row in results:
    transactions.append(tuple(map(str, row)))

with open("phishing_features.tsv", 'w') as f:
    
    for _list in transactions:
        for _string in _list:
            f.write(str(_string) + "\t")

        f.write(str('\n'))
