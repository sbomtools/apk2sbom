"""
Main functions available to apk2sbom
"""

import json
import argparse
from apk2sbom.apkin import get_indices,get_pkgs
from apk2sbom.cdx import map2cdx
from apk2sbom.spdx import map2spdx

def get_pkg_details(image):
    """
    build an array of packages for the given image.
    """
    indices=get_indices()
    packs=get_pkgs(image)
    these_packs=[]
    for i in indices:
        for pack in packs:
            if i['P'] == pack:
                these_packs.append(i)
    return these_packs

def apk2sbom(image,sbom_type):
    """
    return an sbom, given an image and an SBOM type.  SBOM types
    can be 'spdx' or 'cyclonedx'.
    """
    pkgs=get_pkg_details(image)
    if sbom_type == 'spdx':
        return map2spdx(pkgs)
    return map2cdx(pkgs)

def cli():
    """
    Function to call CLI routines to invoke apk2sbom
    """
    parser= argparse.ArgumentParser(description="search SBOM for packages")
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-c','--cyclonedx',\
                       help="Generate CycloneDX JSON output",\
                       action='store_true')
    group.add_argument('-s','--spdx',\
                       help="Generate SPDX JSON output",\
                       action='store_true')
    parser.add_argument('image',help="The name of the docker image")

    args=parser.parse_args()

    if args.cyclonedx:
        sbom_type='cyclonedx'
    else:
        sbom_type='spdx'

    try:
        print(json.dumps(apk2sbom(args.image,sbom_type)))
    except Exception as sbom_error:
        print(str(sbom_error))
