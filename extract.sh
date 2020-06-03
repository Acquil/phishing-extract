sudo apt install whois -y
sudo apt install netbase -y

pip3 install -r requirements.txt -y
pip3 install whois timeout-decorator beautifulsoup4 geoip2 tldextract -y

wget https://raw.githubusercontent.com/Acquil/PhishingWebsitePredictor/master/PhishingWebsitePredictor/GeoLite2-ASN.mmdb
wget https://raw.githubusercontent.com/Acquil/PhishingWebsitePredictor/master/PhishingWebsitePredictor/GeoLite2-Country.mmdb

python3 extract.py