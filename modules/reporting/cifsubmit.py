# Copyright (C) 2012 REN-ISAC
import os
import json
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError
from httplib2 import Http
from urllib import urlencode

class CifSubmit(Report):
    """Saves analysis results in JSON format."""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        self.results = results
        try:
            data = dict(address=results['file']['md5'], impact="malware/exploit", 
                    description="Automated Analysis from Cuckoo "+results['info']['version'], 
                    source='Cuckoo Sandbox', confidence='50', severity='low', restriction='public', guid='everyone')
            self.sendToCif(json.dumps([data]))
            if 'network' in self.results and isinstance(self.results['network'], dict):
                # add hosts seen in communication
                if 'hosts' in self.results['network'] and isinstance(self.results['network']['hosts'], list):
                    # add the host objects first
                    for host in self.results['network']['hosts']:
                        data = dict(address=host, impact="networks", 
                                    description="Observed in Automated Cuckoo Analysis of file: "+results['file']['md5'],
                                    source='Cuckoo Sandbox', confidence='25', severity='low', restriction='public', guid='everyone',
                                    protocol='4')
                        self.sendToCif(json.dumps([data]))
            
          
        except (TypeError, IOError) as e:
            raise CuckooReportError("Failed to submit to CIF Server: %s" % e)
    
    def sendToCif(self,jstring):
        url = self.options["api_url"]
        key = self.options["api_writekey"]
        fullurl = url+'/?apikey='+key+'&fmt=json'
        h = Http(disable_ssl_certificate_validation=True)
        resp, content = h.request(fullurl, "POST", jstring)
