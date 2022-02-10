# Welcome to apk2sbom

**WARNING**

This package is early in development.  May cause warts or indigestion.
Save your work.  Interfaces subject to change without notice.

This package produces an SBOM for an Alpine image out of the Alpine APK.

## Building

1. Bop the version on setup.cfg
2. python3 -m build -w
3. cd dist
4. pip3 install that file


## Usage

    apk2sbom ( -c | -s ) docker-image-name

Where-
 - -c produces cyclonedx
 - -s produces spdx.
 - and the docker image name is just that.   

