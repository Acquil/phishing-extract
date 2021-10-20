from scrapy.crawler import CrawlerProcess

from sitecrawl.spiders.spider import PhishSpider, LegitSpider

# Run all spiders
process = CrawlerProcess()
process.crawl(PhishSpider)
process.crawl(LegitSpider)
# the script will block here until all crawling jobs are finished
process.start()