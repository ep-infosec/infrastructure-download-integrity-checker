#!/usr/bin/env python3
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""python-gnupg CLI"""

from pprint import pprint
import sys
import tempfile
from datetime import datetime, timezone
import logging
import gnupg

def epoch(stamp):
    if stamp == '':
        return f"No expiry date '{stamp}'"
    return datetime.fromtimestamp(int(stamp), timezone.utc).strftime(f"%Y-%m-%d %H:%M:%S %z '{stamp}'")

def main():
    debug = '--debug' in sys.argv
    if debug:
        sys.argv.remove('--debug')
        logger = logging.getLogger('gnupg')
        logger.addHandler(logging.StreamHandler(sys.stdout))
    keyfile = asc_filepath = filepath = None
    if len(sys.argv) == 4:
        (keyfile, asc_filepath, filepath) = sys.argv[1:]
    elif len(sys.argv) == 3:
        (keyfile, filepath)= sys.argv[1:]
        asc_filepath = filepath + '.asc'
    else:
        print("Expecting KEYS [ascfile] artifact")
        sys.exit(1)
    
    tmpdir = tempfile.TemporaryDirectory() # must be stored in var to keep it alive
    project_gpg_dir = tmpdir.name

    keychain = gnupg.GPG(gnupghome=project_gpg_dir, use_agent=True)

    print("Loading KEYS")
    keychain.import_keys(open(keyfile, "rb").read())

    if debug:
        logger.setLevel('DEBUG') # after KEYS!

    print(f"Loaded KEYS, now verify: {asc_filepath} {filepath}")

    verified = keychain.verify_file(open(asc_filepath, "rb"), data_filename=filepath)

    print("Verification data")
    print("=================")
    print(f"valid: {verified.valid}")

    print(f"creation_date: {verified.creation_date}")
    print(f"expire_timestamp: {verified.expire_timestamp}")
    print(f"fingerprint: {verified.fingerprint}")
    print(f"key_id: {verified.key_id}")
    print(f"key_status: {verified.key_status}")
    print(f"pubkey_fingerprint: {verified.pubkey_fingerprint}")
    print(f"sig_timestamp: {verified.sig_timestamp}")
    print(f"signature_id: {verified.signature_id}")
    print(f"status: {verified.status}")
    print(f"timestamp: {verified.timestamp}")
    print(f"trust_text: {verified.trust_text}")
    print(f"trust_level: {verified.trust_level}")
    print(f"username: {verified.username}")

    print("sig_info:")
    pprint(verified.sig_info)

    print("")

    if verified.key_id:
        if debug:
            logger.setLevel('INFO') # noisy
        keys = keychain.list_keys(False, [verified.key_id])
        if not keys:
            print(f"Could not find key entry for {verified.key_id}")
        else:
            key = keys[0] # Assume a single key was found
            print("list_keys info")
            print("==============")
            pprint(key)
            print("")
            print("=============")
            if verified.key_id == key['keyid']:
                print('primary key')
                data = key
                print("created: " + epoch(data['date']))
                print("expires: " + epoch(data['expires']))
            elif verified.key_id in key['subkey_info']:
                print('sub key')
                data = key['subkey_info'][verified.key_id]
                print("created: " + epoch(data['date']))
                print("expires: " + epoch(data['expires']))
            else:
                print(f"Should not happen: could not find {verified.key_id}")


if __name__ == "__main__":
    main()
