# © Copyright 2021 HP Development Company, L.P.
import hashlib
import re
import sys
from urllib.parse import urlparse

class SubCrawlHelpers:

    def get_sha256(data):
        hash_object = hashlib.sha256(data)
        return hash_object.hexdigest()

    def save_content(file_name, data):
        with open(file_name, "wb") as file:
            file.write(data)

    def defang_url(url):
        parsed_url = urlparse(url)
        last_dot = parsed_url.netloc.rindex('.')
        defanged = parsed_url.netloc[0:last_dot] + '[.]' + parsed_url.netloc[last_dot + 1:]
        return url.replace(parsed_url.netloc, defanged).replace('http', 'hxxp')

    def get_config(cfg, collection, key):
        try:
            return cfg[collection][key]
        except Exception as e:
            sys.exit("[ENGINE] Error loading configuration: "
                     + collection + " : " + key)
