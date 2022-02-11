"""
Cache processing for apk2sbom
"""

import re
from os import makedirs,chdir,remove
from tempfile import TemporaryDirectory
import urllib.request
import tarfile
from base64 import b64decode
import docker
from apk2sbom.statics import apkindices

def get_pkgs(image_name):
    """
    Crack a docker image; issue apk command.
    """
    client = docker.from_env()
    resp= client.containers.run(image_name,'apk info')
    packs=re.split('\n',resp.decode(),flags=re.M)
    if not packs[-1]:
        packs.pop(-1)
    return packs

def apk2json(apkfile,entries = False):
    """
    read apk file into a json array.
    """

    if not entries:
        entries=[]

    a_fp=open(apkfile,'r',encoding='utf-8')

    line=a_fp.readline(4096)

    newent={}

    while line:
        if line != '\n':
            line = line[:-1]
            entry=re.split(':[ ]*',line,maxsplit=1)
            newent[entry[0]] = entry[1]
        else:
            newent['C'] = b64decode(newent['C'][2:]).hex()
            entries.append(newent)
            newent={}
        line= a_fp.readline(4096)
    if newent:
        newent['C'] = b64decode(newent['C'][2:]).hex()
        entries.append(newent)
    a_fp.close()
    return entries

def get_indices():
    """
    Retrieve and process APKINDEX files.
    """
    index_dir=TemporaryDirectory()
    # ToDo: for python 3.10 add 'ignore_cleanup_errors=True'
    chdir(index_dir.name)
    entries=[]
    ind_file='apkindex.tgz'
    for url in apkindices:
        urllib.request.urlretrieve(url,ind_file)
        with tarfile.open(ind_file) as index_tar:
            index_tar.extract('APKINDEX',path='.')
        entries=apk2json('APKINDEX',entries)
        remove('APKINDEX')
        remove(ind_file)
    chdir('..')
    index_dir.cleanup()
    return entries

def get_depend(pkgs,item):
    """
    Provide the package name that contains the item in its p entry or
    return False
    """
    for pkg in pkgs:
        if 'p' in pkg:
            plist=re.split(' ',pkg['p'])
            for plist_i in plist:
                if re.match('.*'+item+'.*',plist_i):
                    return pkg['P']
    return False
