"""
Process licensing information when necessary.
"""

import json
import pkg_resources


def license_type(ltext):
    """
    return true or false on whether something is an SPDX license
    """
    if ' AND ' in ltext or ' OR ' in ltext:
        return {
            "expression" : ltext
            }

    spdx_file = json.loads(pkg_resources.resource_string('apk2sbom',
                                                        'data/licenses.json'))
    for license_entry in spdx_file['licenses']:
        if license_entry['licenseId'] == ltext:
            return {
                "license" : {
                    "id" : ltext
                    }
                }
    return {
        "license" : {
            "name" : ltext
        }
    }
