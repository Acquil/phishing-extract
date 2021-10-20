FROM python:3.8.6


#set up environment
RUN apt-get update && apt-get -y install apt-utils\
    && apt-get install --no-install-recommends --no-install-suggests -y curl \
    && apt-get -y install wget \
    && apt-get install unzip \
    && apt-get -y install git \
    && apt-get -y install whois \
    && apt-get -y install netbase


WORKDIR /usr/src
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


WORKDIR /usr/src/data
# Copy mmdb files
RUN wget  https://raw.githubusercontent.com/Acquil/phishing-extract/master/phishing-extract/GeoLite2-ASN.mmdb
          && echo "ASN data downloaded"
RUN wget  https://raw.githubusercontent.com/Acquil/phishing-extract/master/phishing-extract/GeoLite2-Country.mmdb 
          && echo "Country data downloaded"

# pip3 otherwise
RUN pip install install whois timeout-decorator beautifulsoup4 geoip2 tldextract -y

WORKDIR /usr/src

#COPY ALL FILES TO CONTAINER
COPY . .

CMD ["python3", "src/crawlers/main.py"]