"""
SPDX processing for apk2sbom
"""

import re
from datetime import datetime
# pylint: disable=no-name-in-module
from socket import gethostname
from apk2sbom.apkin import get_depend

def map2spdx(installed_pkgs):
    """
    take a package list and create a CycloneDX JSON object.
    """
    pkgs = [ ]
    deps = []

    sbom = {
        "spdxVersion" : "SPDX-2.2",
        "SPDXID" : "SPDXRef-DOCUMENT",
        "dataLicense" : "CC0-1.0",
        "name" : "apt2sbom-" + gethostname(),
        "documentNamespace" : "https://" + gethostname() + "/.well-known/transparency/sbom",
        'creationInfo' : {
            'creators' : [ 'Tool: apk2sbom' ],
            'created' : str(re.sub(r'..*$','',datetime.now().isoformat())) + 'Z'
            }
    }

    pkgids = []

    for pkg in installed_pkgs:
        pack = {
            'name' : pkg['P'],
            'SPDXID' : 'SPDXRef-apk2sbom.' + pkg['P'],
            'versionInfo' : pkg['V'],
            'filesAnalyzed' : False,
            'supplier' : 'Organization: ' +  pkg['m'],
            'homepage' : pkg['U'],
            'checksums': [ {
                'algorithm' : 'SHA1',
                'checksumValue' : pkg['C']
                } ],
            'downloadLocation' : "http://spdx.org/rdf/terms#noassertion",
            'licenseConcluded' : 'NOASSERTION',
            'copyrightText' : 'NOASSERTION'
            }
        pkgids.append(pack['SPDXID'])

        if 'L' in pkg:
            pack['licenseDeclared'] =  pkg['L']
        pkgs.append(pack)
        if 'D' in pkg:
            for depend in re.split(' ',pkg['D']):
                if re.match('so:',depend):
                    depend= re.sub('(so:)','',depend)
                    dep2=get_depend(installed_pkgs,depend)
                    if not dep2:
                        print(f'burp: {depend}')
                        continue
                    depend=dep2
                deps.append({
                  'spdxElementId' : pack['SPDXID'],
                  'relationshipType' : 'DEPENDS_ON',
                  'relatedSpdxElement' : "SPDXRef-apt2sbom." + \
                    re.sub('[>=].*','',depend)
                    })

    sbom['packages'] = pkgs
    sbom['documentDescribes'] = pkgids
    if deps:
        sbom['relationships']=deps

    return sbom
