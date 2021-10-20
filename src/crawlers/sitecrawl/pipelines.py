#  Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://docs.scrapy.org/en/latest/topics/item-pipeline.html


import json
from uuid import uuid4

import pymongo
# useful for handling different item types with a single interface
from itemadapter import ItemAdapter
from scrapy.exceptions import DropItem


class StackPipeline:
    def process_item(self, item, spider):
        return item


# Additional Pipelines should be enabled in settings.py
class JsonWriterPipeline:

    def open_spider(self, spider):
        self.file = open(f'{uuid4()}_items.jsonl', "a")

    def close_spider(self, spider):
        self.file.close()

    def process_item(self, item, spider):
        line = json.dumps(ItemAdapter(item).asdict()) + "\n"
        self.file.write(line)
        return item


class DuplicatesPipeline:

    def __init__(self):
        self.ids_seen = set()

    def process_item(self, item, spider):
        adapter = ItemAdapter(item)
        if adapter['url'] in self.ids_seen:
            raise DropItem("Duplicate item found: %r" % item)
        else:
            self.ids_seen.add(adapter['url'])
            return item