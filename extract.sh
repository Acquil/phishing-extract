sudo apt install whois
sudo apt install netbase

pip3 install whois timeout-decorator beautifulsoup4 geoip2 tldextract

%shell wget https://raw.githubusercontent.com/Acquil/PhishingWebsitePredictor/master/PhishingWebsitePredictor/GeoLite2-ASN.mmdb
%shell wget https://raw.githubusercontent.com/Acquil/PhishingWebsitePredictor/master/PhishingWebsitePredictor/GeoLite2-Country.mmdb

python3 extract.py