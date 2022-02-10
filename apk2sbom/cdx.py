"""
CycloneDX generator for apk2sbom
"""



from uuid import uuid4
import re
from datetime import datetime
from apk2sbom.apkin import get_depend
from apk2sbom.license import license_type
def map2cdx(installed_pkgs):
    """
    take a package list and create a CycloneDX JSON object.
    """
    pkgs = [ ]
    deps = []

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:" + str(uuid4()),
        "version": 1
        }
    meta = {
        "timestamp": re.sub(r'[.].*$','',str(datetime.now().isoformat())) + 'Z',
        "tools" : [ {
            "vendor" : "Eliot Lear",
            "name" : "apk2sbom",
            } ],
        "component" : {
            "type" : "container",
            "name" : "alpine-derived-container",
            "version" : "1"
            },
        "licenses" : [ { "license" : {
            "id" : "BSD-3-Clause"
            }
        } ]
      }
    sbom['metadata']= meta

    for pkg in installed_pkgs:
        pack = {
            'type' : 'application',
            'name' : pkg['P'],
            'version' : pkg['V'],
            'bom-ref' : pkg['P'],
            'supplier' : {
                'name' : pkg['m'],
                'url' : [ pkg['U'] ]
                },
            'hashes': [ {
                'alg' : 'SHA-1',
                'content' : pkg['C']
                } ]
            }
        if 'L' in pkg:
            pack['licenses'] =  [
                license_type(pkg['L'])
            ]
        pkgs.append(pack)
        if 'D' in pkg:
            dep_list = []
            for depend in re.split(' ',pkg['D']):
                if re.match('so:',depend):
                    depend= re.sub('(so:)','',depend)
                    dep2=get_depend(installed_pkgs,depend)
                    if not dep2:
                        print(f'burp: {depend}')
                        continue
                    depend=dep2
                depend=re.sub('[>=].*','',depend)
                if depend not in dep_list:
                    dep_list.append(re.sub('[>=].*','',depend))
            dep = {
                'ref' : pack['bom-ref'],
                'dependsOn' : dep_list
            }
            deps.append(dep)

    if pkgs:
        sbom['components'] = pkgs
    if deps:
        sbom['dependencies']=deps

    return sbom
