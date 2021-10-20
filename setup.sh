sudo apt install whois -y
sudo apt install netbase -y


python3 -m venv .venv
source .venv/bin/activate
pip install -r src/requirements.txt
pip install whois timeout-decorator beautifulsoup4 geoip2 tldextract

wget https://raw.githubusercontent.com/Acquil/phishing-extract/master/phishing-extract/GeoLite2-ASN.mmdb
wget https://raw.githubusercontent.com/Acquil/phishing-extract/master/phishing-extract/GeoLite2-Country.mmdb 
