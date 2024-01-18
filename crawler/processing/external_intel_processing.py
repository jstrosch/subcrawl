import hashlib
import os
import magic
import requests
import json
from utils import SubCrawlColors, SubCrawlHelpers

from .default_processing import DefaultProcessing


class ExternalIntelProcessing(DefaultProcessing):

    cfg = None
    logger = None
    vt_api = None
    urlhaus_api = None
    bazaar_api = None
    submit_urlhaus = False
    submit_bazaar = False

    vt_api_url = "https://www.virustotal.com/api/v3/files/"
    urlhaus_api_url = "https://urlhaus-api.abuse.ch/v1/payload/"
    urlhaus_api_submit = "https://urlhaus.abuse.ch/api/"
    bazaar_api_url = "https://mb-api.abuse.ch/api/v1/"

    def __init__(self, config, logger):
        self.cfg = config
        self.logger = logger

        if "<" in SubCrawlHelpers.get_config(self.cfg, "external_intel", "vt_api"):
            self.logger.info(SubCrawlColors.YELLOW + '[ExternalIntel] VirusTotal API Key not set' +
                                                        SubCrawlColors.RESET)
        else:
            self.vt_api = SubCrawlHelpers.get_config(
                                self.cfg, "external_intel", "vt_api")

        if "<" in SubCrawlHelpers.get_config(self.cfg, "external_intel", "urlhaus_api"):
            self.logger.info(SubCrawlColors.YELLOW + '[ExternalIntel] URLHaus API Key not set' +
                                                        SubCrawlColors.RESET)
        else:
            self.urlhaus_api = SubCrawlHelpers.get_config(self.cfg, "external_intel", "urlhaus_api")

        if "<" in SubCrawlHelpers.get_config(self.cfg, "external_intel", "bazaar_api"):
            self.logger.info(SubCrawlColors.YELLOW + '[ExternalIntel] Bazaar API Key not set' +
                                                        SubCrawlColors.RESET)
        else:
            self.bazaar_api = SubCrawlHelpers.get_config(self.cfg, "external_intel", "bazaar_api")

        self.submit_urlhaus = SubCrawlHelpers.get_config(self.cfg, "external_intel", "submit_urlhaus")
        if not self.submit_urlhaus:
            self.logger.info(SubCrawlColors.YELLOW + '[ExternalIntel] Not uploading to URLHaus' + SubCrawlColors.RESET)

        self.submit_bazaar = SubCrawlHelpers.get_config(self.cfg, "external_intel", "submit_bazaar")
        if not self.submit_bazaar:
            self.logger.info(SubCrawlColors.YELLOW + '[ExternalIntel] Not uploading to Bazaar' + SubCrawlColors.RESET)


    def process(self, url, content):
        payload = {}
        content_match = True
        signature = None

        shasum = SubCrawlHelpers.get_sha256(content)
        content_magic = magic.from_buffer(content).lower()
        
        tags = []
        if content_magic and any(partial in content_magic for partial in
               SubCrawlHelpers.get_config(self.cfg, "crawler", "pe_magics")):

            if "(dll)" in content_magic:
                tags.append("dll")
            else:
                tags.append("exe")
            
            if "x86-64" in content_magic:
                tags.append("x64")

            if "mono/.net" in content_magic:
                tags.append('.NET')
                tags.append('MSIL')

            if not self.urlhaus_api is None:
                signature = self.check_urlhaus(shasum, url, tags)

            if not self.bazaar_api is None:
                signature = self.check_bazaar(shasum, url, content, tags)

            if not self.vt_api is None:
                self.logger.info(SubCrawlColors.CYAN + "[ExternalIntel] File status on VirusTotal:\t" +
                    self.check_virustotal(shasum) + " \t\t(" + shasum + ")" + SubCrawlColors.RESET)
        elif content_magic and any(partial in content_magic for partial in
               SubCrawlHelpers.get_config(self.cfg, "crawler", "office_magics")):
            
            if "Microsoft Word" in content_magic or "Microsoft Office Word" in content_magic:
                tags.append("doc")
            elif "Microsoft Excel" in content_magic:
                tags.append('xls')
            elif "Rich Text Format" in content_magic:
                tags.append('rtf')
            elif "CDFV2 Encrypted" in content_magic:
                tags.append('encrypted')

            if not self.urlhaus_api is None:
                signature = self.check_urlhaus(shasum, url, tags)

            if not self.bazaar_api is None:
                signature = self.check_bazaar(shasum, url, content, tags)

        else:
            content_match = False

        if content_match:
            payload = {"hash": shasum, "url": url, "signature": signature}

        return payload

    def check_urlhaus(self, sha256, url, tags):
        status = SubCrawlColors.YELLOW + "NOT FOUND" + SubCrawlColors.CYAN
        signature = None
        sample_found = False
        post_data = {'sha256_hash': sha256}
        resp = requests.post(self.urlhaus_api_url, data = post_data)

        results = json.loads(resp.text)

        if results["query_status"] == "ok":
            status = "FOUND - "
            sample_found = True
            if not results['signature'] is None:
                status += results['signature']
                signature = results['signature']
            else:
                status += "No Signature"
            
        self.logger.info(SubCrawlColors.CYAN + "[ExternalIntel] File status on URLHaus:\t" + status + "\t\t(" + sha256 + ")" + SubCrawlColors.RESET)
        
        if not sample_found and self.submit_urlhaus:
            self.logger.info(SubCrawlColors.PURPLE + "[ExternalIntel] Submitting file to URLHaus:\t" + url + SubCrawlColors.RESET)
            jsonDataURLHaus = {
                'token' : self.urlhaus_api,
                'anonymous' : '0',
                'submission' : [
                    {
                        'url': url,
                        'threat': 'malware_download',
                        'tags': 
                            tags
                    }
                ]
            }

            headers = {
                "Content-Type" : "application/json"
            }
            r = requests.post(self.urlhaus_api_submit, json=jsonDataURLHaus, timeout=15, headers=headers)
            if "inserted" in r.content.decode("utf-8"):
                self.logger.info(SubCrawlColors.GREEN + "[ExternalIntel] URL Submitted on URLHaus :)" + SubCrawlColors.RESET)
            else:
                self.logger.error(SubCrawlColors.RED + "[ExternalIntel] Problem Submitting URL on URLHaus :(\t" + r.content.decode("utf-8").replace("\n","") + SubCrawlColors.RESET)
        return signature

    def check_bazaar(self, sha256, url, content, tags):
        status = SubCrawlColors.YELLOW + "NOT FOUND" + SubCrawlColors.CYAN
        signature = None
        sample_found = False
        post_data = {'query':'get_info','hash': sha256}
        resp = requests.post(self.bazaar_api_url, data = post_data)
        results = json.loads(resp.text)

        if results["query_status"] == "ok":
            sig = "no sig"
            sample_found = True
            for sample in results['data']:
                if not sample['signature'] is None:
                    sig = sample['signature']
                    signature = sample['signature']
                else:
                    sig = "No Signature"
            status = "FOUND - " + sig
        
        self.logger.info(SubCrawlColors.CYAN + "[ExternalIntel] File status on Bazaar:\t" + status + "\t\t(" + sha256 + ")" + SubCrawlColors.RESET)

        if not sample_found and self.submit_bazaar:
            self.logger.info(SubCrawlColors.PURPLE + "[ExternalIntel] Submitting file to Bazaar:\t" + url + SubCrawlColors.RESET)
            
            jsonDataBazaar = {
                'anonymous' : '0',
                'delivery_method' : 'web_download',
                'tags' : 
                    tags,
                'context': {
                    'comment' : 'Found at ' + SubCrawlHelpers.defang_url(url) + ' by #subcrawl',
                }
            }

            files = {
                'json_data' : (None,json.dumps(jsonDataBazaar), 'application/json'),
                'file' : content
            }
            headers = {'API-KEY' : self.bazaar_api }
            
            r = requests.post(self.bazaar_api_url, files=files, verify=False, headers=headers)

            if "inserted" in r.content.decode("utf-8"):
                 self.logger.info(SubCrawlColors.GREEN + "[ExternalIntel] Payload Submitted on Bazaar :)" + SubCrawlColors.RESET)
            else:
                self.logger.error(SubCrawlColors.RED + "[ExternalIntel] Problem Submitting Payload on Bazaar :(\t" + r.content.decode("utf-8").replace("\n","") + SubCrawlColors.RESET)               
        return signature

    def check_virustotal(self,sha256):
        result = "NOT FOUND"
        headers = {'x-apikey':self.vt_api}
        resp = requests.get(self.vt_api_url + sha256, headers = headers)

        results = json.loads(resp.text)

        if not "error" in results:
            result = "FOUND"

        return result
