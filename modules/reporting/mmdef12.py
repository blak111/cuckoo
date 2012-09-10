# Copyright (C) 2012 REN-ISAC

import os

import lib.mmdef.mmdef12 as mmdef
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.utils import datetime_to_iso


class Report(Report):
    """Generates an MMDEF 1.2 report."""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        self.idMap = {}
        # Save results
        self.results = results
        # Build MAEC doc
        self.addWrapper()
        self.addObjects()
        ##self.addAnalysis()
        ##self.addActions()
        
		# Write report.
        self.output()

    def addWrapper(self):
        """Generates MMDEF malwareMetaData structure."""
        self.idMap['prefix'] = "mmdef:%s" % self.results['file']['md5']

        # Generate the outer xml container and add meta data
        self.m = mmdef.malwareMetaData(
                                id = "%s:bnd:1" % self.idMap['prefix'], 
                                version='1.2'
                                )
        self.m.set_author("Cuckoo Automated Analysis")
        self.m.set_comment("Cuckoo Automated Analysis from Cuckoo "+self.results['info']['version'])
        self.m.set_company("N/A")
        self.m.set_timestamp(datetime_to_iso(self.results["info"]["ended"]))

        # add all of the objects (registry keys, hosts, files, etc that were accessed)
        self.objects = mmdef.objectsType()
        self.m.set_objects(self.objects)
        
        #object properties
        self.objectProperties = mmdef.objectPropertiesType()
        self.m.set_objectProperties(self.objectProperties)
        
        
        # relationships
        self.addedRelationships = [] # use this to prevent duplicate relationships
        self.relationships = mmdef.relationshipsType()
        self.m.set_relationships(self.relationships)

    

    def addObjects(self):
        """Adds all of the objects"""
        # Analyzed File 
        self.setFileObject(self.results['file'])
        # Network Addresses
        if 'network' in self.results and isinstance(self.results['network'], dict):
            # add hosts seen in communication
            if 'hosts' in self.results['network'] and isinstance(self.results['network']['hosts'], list):
                # add the host objects first
                for host in self.results['network']['hosts']:
                    self.objects.add_ip(mmdef.IPObject(id = host + '-' + host,
                                                        startAddress = mmdef.IPAddress('ipv4',host), 
                                                        endAddress = mmdef.IPAddress('ipv4',host)
                                                       )
                                        )
                # add the communications between the objects
                if 'udp' in self.results['network'] and isinstance(self.results['network']['udp'], list):
                    for pkt in self.results['network']['udp']:
                        self.addNetworkRelationship(pkt)
                if 'tcp' in self.results['network'] and isinstance(self.results['network']['tcp'], list):
                    for pkt in self.results['network']['tcp']:
                        self.addNetworkRelationship(pkt)
            
            #add dns addresses
            if 'dns' in self.results['network'] and isinstance(self.results['network']['dns'], list):
                for dns in self.results['network']['dns']:
                    if 'hostname' in dns:
                        self.objects.add_domain(mmdef.domainObject(id=dns['hostname'],domain=dns['hostname']))
            
            #add any http uri's
            if 'http' in self.results['network'] and isinstance(self.results['network']['http'], list):
                for hreq in self.results['network']['http']:
                    if 'uri' in hreq:
                        self.objects.add_uri(mmdef.uriObject(uriString=hreq['uri'], id=hreq['uri']))
            
            
        # Registry keys - found in process behaviors with category of registry
        if 'behavior' in self.results:
            if 'summary' in self.results['behavior']:
                if 'keys' in self.results['behavior']['summary'] and isinstance(self.results['behavior']['summary']['keys'],list):
                    for key in self.results['behavior']['summary']['keys']:
                        self.objects.add_registry(mmdef.registryObject(id = key, key = key))
    
       
    
    def addNetworkRelationship(self,packet):
        """Adds a network communication generic relationship between IP addresses"""
        id = packet['src']+packet['dst']
        # prevent same relationship from being added twice
        if id in self.addedRelationships: return
        self.addedRelationships.append(id)
        rel=mmdef.relationship()
        rel.set_type('relatedTo')
        rel.set_source(mmdef.reference('<ref>ip[@id="'+packet['src']+'-'+packet['src']+'"]</ref>'))
        rel.set_target(mmdef.reference('<ref>ip[@id="'+packet['dst']+'-'+packet['dst']+'"]</ref>'))
        self.relationships.add_relationship(rel)

    def setFileObject(self,fres):
        """Adds the analyzed file"""
        fo = mmdef.fileObject(
                                id = fres['sha256'],
                                sha1 = fres['sha1'],
                                filename = [fres['name']],
                                sha512 = fres['sha512'],
                                crc32 = fres['crc32'],
                                fileType = [fres['type']],
                                sha256 = fres['sha256'],
                                md5 = fres['md5'],
                                size = fres['size']
                             )
        
        self.objects.add_file(fo)


    def output(self):
        """Writes report to disk."""
        try:
            report = open(os.path.join(self.reports_path, "report.mmdef-1.2.xml"), "w")
            report.write('<?xml version="1.0" ?>\n')
            report.write('<!--\n')
            report.write('Cuckoo Sandbox MMDEF 1.2 malware analysis report\n')
            report.write('http://www.cuckoosandbox.org\n')
            report.write('-->\n')
            self.m.export(report, 0, namespace_ = '', name_ = 'malwareMetaData', namespacedef_ = 'xsi:schemaLocation="http://grouper.ieee.org/groups/malware/malwg/Schema1.2/ file:metadataSharing.xsd"')
            report.close()
        except (TypeError, IOError) as e:
            raise CuckooReportError("Failed to generate MMDEF 1.2 report: %s" % e)
