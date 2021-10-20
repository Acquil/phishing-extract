import json
from datetime import datetime

import scrapy
from scrapy import Request

from sitecrawl.items import DataItem
from sitecrawl.spiders.extract import *
import pandas as pd

# noinspection SpellCheckingInspection
class PhishSpider(scrapy.Spider):
    name = 'phish-scraper'
    df = pd.read_json("https://raw.githubusercontent.com/ebubekirbbr/pdd/master/input/data_phishing_37175.json")
    start_urls = list(df[0])

    custom_settings = {
        'FEED_URI': f'data/{name}_' + str(datetime.today()) + '.jsonl',
        'FEED_FORMAT': 'jsonlines',
        'FEED_EXPORTERS': {
            'jsonlines': 'scrapy.exporters.JsonItemExporter',
        },
        'FEED_EXPORT_ENCODING': 'utf-8',
    }

    def parse(self, response, **kwargs):
        
        item = DataItem()
        url = response.url


        r = requests.get(url)
        soup = BeautifulSoup(r.content, "html.parser")

        hostname = get_hostname_from_url(url)

        item['url'] = url
        # ip address in url
        item['f1'] = having_ip_address(url)
        # numbere of dots
        item['f2'] = num_dots(url)
        # number of subdomains
        item['f3'] = num_subdomain(url)
        # number of urls
        item['f4'] = num_levels_url(url)
        # length of urls
        item['f5'] = url_length(url)
        # number of hyphens in entire url
        item['f6'] = num_hyphens(url)
        # number of hyphens in hostname
        item['f7'] = num_hyphens_hostname(url)
        # number of @ in url
        item['f8'] = num_at_symbol(url)
        # number of ~ in url
        item['f9'] = num_tilde_symbol(url)
        # number of & in url
        item['f10'] = num_ampersand(url)
        # number of # in url
        item['f11'] = num_hash_symbol(url)
        # number of query parts
        item['f12'] = num_query_parts(url)
        # number of sensitive words
        item['f13'] = num_sensitive_words(url)

        item['f14'] = shortening_service(url)
        item['f15'] = double_slash_redirecting(url)
        # item[] = having_sub_domain(url)
        item['f16'] = unicode_in_url(url)

        # ASN
        item['asn'] = get_asn_org(asn_reader, url)
        # Domain country
        item['country'] = get_domain_reg_country_code(country_reader, url)

        domain = tldextract.extract(url).fqdn
        #    dns = 1
        #    try:
        #        domain = whois.query(hostname)
        #    except Exception as err:
        #        print(err)
        #        dns = -1

        item['f17'] = https_token(url)
        #    item[] = "DNS unsuccessful" if dns == -1 else domain_registration_length(domain)
        # item[] = age_of_domain(domain)
        item['f18'] = favicon(url, soup, hostname)
        #    if dns==1:
        #        item[] = abnormal_url(domain.name, url)
        #    else:
        #        item[] = abnormal_url(domain, url)

        item['f19'] = url_of_anchor(url, soup, hostname)
        item['f20'] = links_in_tags(url, soup, hostname)
        item['f21'] = i_frame(soup)
        item['f22'] = check_suspicious_js(soup)
        item['f23'] = check_popup_js(soup)
        item['cls'] = "Phishing"
        yield item



# noinspection SpellCheckingInspection
class LegitSpider(scrapy.Spider):
    name = 'phish-scraper-legit' 
    df = pd.read_json("https://raw.githubusercontent.com/ebubekirbbr/pdd/master/input/data_legitimate_36400.json")
    start_urls = list(df[0])

    custom_settings = {
        'FEED_URI': f'data/{name}_' + str(datetime.today()) + '.jsonl',
        'FEED_FORMAT': 'jsonlines',
        'FEED_EXPORTERS': {
            'jsonlines': 'scrapy.exporters.JsonItemExporter',
        },
        'FEED_EXPORT_ENCODING': 'utf-8',
    }

    def parse(self, response, **kwargs):
        
        item = DataItem()
        url = response.url


        r = requests.get(url)
        soup = BeautifulSoup(r.content, "html.parser")

        hostname = get_hostname_from_url(url)

        item['url'] = url
        # ip address in url
        item['f1'] = having_ip_address(url)
        # numbere of dots
        item['f2'] = num_dots(url)
        # number of subdomains
        item['f3'] = num_subdomain(url)
        # number of urls
        item['f4'] = num_levels_url(url)
        # length of urls
        item['f5'] = url_length(url)
        # number of hyphens in entire url
        item['f6'] = num_hyphens(url)
        # number of hyphens in hostname
        item['f7'] = num_hyphens_hostname(url)
        # number of @ in url
        item['f8'] = num_at_symbol(url)
        # number of ~ in url
        item['f9'] = num_tilde_symbol(url)
        # number of & in url
        item['f10'] = num_ampersand(url)
        # number of # in url
        item['f11'] = num_hash_symbol(url)
        # number of query parts
        item['f12'] = num_query_parts(url)
        # number of sensitive words
        item['f13'] = num_sensitive_words(url)

        item['f14'] = shortening_service(url)
        item['f15'] = double_slash_redirecting(url)
        # item[] = having_sub_domain(url)
        item['f16'] = unicode_in_url(url)

        # ASN
        item['asn'] = get_asn_org(asn_reader, url)
        # Domain country
        item['country'] = get_domain_reg_country_code(country_reader, url)

        domain = tldextract.extract(url).fqdn
        #    dns = 1
        #    try:
        #        domain = whois.query(hostname)
        #    except Exception as err:
        #        print(err)
        #        dns = -1

        item['f17'] = https_token(url)
        #    item[] = "DNS unsuccessful" if dns == -1 else domain_registration_length(domain)
        # item[] = age_of_domain(domain)
        item['f18'] = favicon(url, soup, hostname)
        #    if dns==1:
        #        item[] = abnormal_url(domain.name, url)
        #    else:
        #        item[] = abnormal_url(domain, url)

        item['f19'] = url_of_anchor(url, soup, hostname)
        item['f20'] = links_in_tags(url, soup, hostname)
        item['f21'] = i_frame(soup)
        item['f22'] = check_suspicious_js(soup)
        item['f23'] = check_popup_js(soup)
        item['cls'] = "Legitimate"
        yield item
