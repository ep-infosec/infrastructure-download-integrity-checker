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
"""ASF Infrastructure Download Integrity Checker"""
import os
import gnupg
import yaml
import asfpy.messaging
import hashlib
import requests
import time
import sys
import string
import typing

# gnpug version 0.4.9 overwrites the key_id for two message types when it should not
# fix up the code to reset the value
if gnupg.__version__ == '0.4.9':
    handle = gnupg.Verify.handle_status # original method

    def override_handle_status(self, key ,value):
        save = self.key_id # in case we need to restore it
        handle(self, key, value) # call original code
        if key in ('UNEXPECTED', 'FAILURE'):
            self.key_id = save # restore the overwritten value

    # add our override method
    gnupg.Verify.handle_status = override_handle_status

CHUNK_SIZE = 4096
CFG = yaml.safe_load(open("./checker.yaml"))
assert CFG.get("gpg_homedir"), "Please specify a homedir for the GPG keychain!"

WHIMSY_MAIL_MAP = "https://whimsy.apache.org/public/committee-info.json"
WHIMSY_PROJECTS_LIST = "https://whimsy.apache.org/public/public_ldap_projects.json"
MAIL_MAP = requests.get(WHIMSY_MAIL_MAP).json()["committees"]
PROJECTS_LIST = requests.get(WHIMSY_PROJECTS_LIST).json()["projects"]
EMAIL_TEMPLATE = open("email-template.txt", "r").read()
INTERVAL = 1800  # Sleep for 30 min if --forever is set, then repeat
CHECKSUM_LENGTHS = {
    "md5": 128,
    "sha1": 160,
    "sha256": 256,
    "sha512": 512,
}


def alert_project(project: str, errors: dict):
    """Sends a notification to the project and infra aboot errors that were found"""
    if errors:
        if project not in PROJECTS_LIST:  # Only notify for actual, existing projects
            return
        project_list = f"private@{project}.apache.org"  # Standard naming
        if project in MAIL_MAP:
            project_list = f"private@{MAIL_MAP[project]['mail_list']}.apache.org"  # Special case for certain committees
        recipients = [project_list]
        extra_recips = CFG.get("extra_recipients")
        if isinstance(extra_recips, list):
            recipients.extend(extra_recips)
        errormsg = ""
        for filepath, errorlines in errors.items():
            errormsg += f"  - Errors were found while verifying {filepath}:\n"
            for errorline in errorlines:
                errormsg += f"    - {errorline}\n"
            errormsg += "\n"
        if "--debug" not in sys.argv:  # Don't send emails if --debug is specified
            print(f"Dispatching email to: {recipients}")
            asfpy.messaging.mail(
                sender="ASF Infrastructure <root@apache.org>",
                subject=f"Verification of download artifacts on dist.apache.org FAILED for {project}!",
                recipients=recipients,
                message=EMAIL_TEMPLATE.format(**locals())
            )
        else:
            print(errormsg)
            sys.stdout.flush()


def load_keys(project: str, is_podling: bool) -> gnupg.GPG:
    """Loads all keys found in KEYS files for a project and returns the GPG toolchain object holding said keys"""
    project_dir = os.path.join(CFG["dist_dir"], project) if not is_podling else os.path.join(CFG["dist_dir"], "incubator", project)
    project_gpg_dir = os.path.join(CFG["gpg_homedir"], project) if not is_podling else os.path.join(CFG["gpg_homedir"], "incubator", project)
    assert project and os.path.isdir(project_dir), f"Project not specified or no project dist directory found for {project}!"
    if not os.path.isdir(project_gpg_dir):
        os.makedirs(project_gpg_dir, exist_ok=True)
    keychain = gnupg.GPG(gnupghome=project_gpg_dir, use_agent=True)
    for root, _dirs, files in os.walk(project_dir):
        for filename in files:
            filepath = os.path.join(root, filename)
            if filename in ["KEYS", "KEYS.txt"]:
                if "--quiet" not in sys.argv:
                    print(f"Loading {filepath} into toolchain")
                keychain.import_keys(open(filepath, "rb").read())
    return keychain


def digest(filepath: str, method: str) -> str:
    """Calculates and returns the checksum of a file given a file path and a digest method (sha256, sha512 etc)"""
    digester = hashlib.new(method)
    with open(filepath, "rb") as file:
        for chunk in iter(lambda: file.read(CHUNK_SIZE), b''):
            digester.update(chunk)
    return digester.hexdigest()


def verify_checksum(filepath: str, method: str) -> list:
    """Verifies a filepath against its checksum file, given a checksum method. Returns a list of errors if any found"""
    filename = os.path.basename(filepath)
    checksum_filepath = filepath + "." + method  # foo.sha256
    if not os.path.exists(checksum_filepath):
        checksum_filepath = filepath + "." + method.upper()  # foo.SHA256 fallback
    checksum_filename = os.path.basename(checksum_filepath)
    errors = []
    try:
        try:
            checksum_value = open(checksum_filepath, "r", encoding="utf-8").read()
        except UnicodeDecodeError:  # UTF-16??
            checksum_value = open(checksum_filepath, "r", encoding="utf-16").read()
    except UnicodeError as e:
        errors.append(f"[CHK06] Checksum file {checksum_filename} contains garbage characters: {e}")
        return errors
    checksum_value_trimmed = ""
    # Strip away comment lines first
    for line in checksum_value.split("\n"):
        if not line.startswith("//") and not line.startswith("#"):
            checksum_value_trimmed += line.strip() + " "
    checksum_options = checksum_value_trimmed.split(" ")
    checksum_on_disk = "".join(x.strip() for x in checksum_options if all(c in string.hexdigits for c in x.strip())).lower()
    checksum_calculated = digest(filepath, method)
    if checksum_on_disk != checksum_calculated:
        errors.append(f"[CHK06] Checksum does not match checksum file {checksum_filename}!")
        errors.append(f"[CHK06] Calculated {method} checksum of {filename} was: {checksum_calculated}")
        errors.append(f"[CHK06] Checksum file {checksum_filename} said it should have been: {checksum_on_disk}")
        # Simple check for whether this file is just typoed.
        if len(checksum_on_disk) != CHECKSUM_LENGTHS[method]/4:  # Wrong filetype??
            for m, l in CHECKSUM_LENGTHS.items():
                if len(checksum_on_disk) == l/4:
                    errors.append(f"[CHK06] {checksum_filename} looks like it could be a {m} checksum, but has a {method} extension!")
                    break
    return errors


def push_error(edict: dict, filepath: str, errmsg: typing.Union[str, list]):
    """Push an error message to the error dict, creating an entry if none exists, otherwise appending to it"""
    if filepath not in edict:
        edict[filepath] = list()
    if isinstance(errmsg, list):
        edict[filepath].extend(errmsg)
    else:
        edict[filepath].append(errmsg)


def verify_files(project: str, keychain: gnupg.GPG, is_podling: bool) -> dict:
    """Verifies all download artifacts in a directory using the supplied keychain. Returns a dict of filenames and
    their corresponding error messages if checksum or signature errors were found."""
    errors: typing.Dict[str, str] = dict()
    path = os.path.join(CFG["dist_dir"], project) if not is_podling else os.path.join(CFG["dist_dir"], "incubator", project)
    known_exts = CFG.get("known_extensions")
    strong_checksum_deadline = CFG.get("strong_checksum_deadline", 0)  # If applicable, only require sha1/md5 for older files
    # Check that we HAVE keys in the key chain
    if not keychain.list_keys():
        dl_files = os.listdir(path)
        if not dl_files or (len(dl_files) == 1 and dl_files[0] == ".htaccess"):  # Attic'ed project, skip it!
            return errors
        push_error(errors, "KEYS", "[CHK03] KEYS file could not be read or did not contain any valid signing keys!")
    # Now check all files...
    for root, _dirs, files in os.walk(path):
        for filename in sorted(files):
            extension = filename.split(".")[-1] if "." in filename else ""
            if extension in known_exts:
                filepath = os.path.join(root, filename)
                if os.path.islink(filepath):  # Skip symlinks
                    continue
                if "--quiet" not in sys.argv:
                    print(f"Verifying {filepath}")
                valid_checksums_found = 0
                valid_weak_checksums_found = 0
                # Verify strong checksums
                for method in CFG.get("strong_checksums"):
                    chkfile = filepath + "." + method
                    chkfile_uc = filepath + "." + method.upper()  # Uppercase extension? :(
                    if os.path.exists(chkfile) or os.path.exists(chkfile_uc):
                        file_errors = verify_checksum(filepath, method)
                        if file_errors:
                            push_error(errors, filepath, file_errors)
                        else:
                            valid_checksums_found += 1

                # Check older algos, but only count if release is old enough
                for method in CFG.get("weak_checksums"):
                    chkfile = filepath + "." + method
                    chkfile_uc = filepath + "." + method.upper()  # Uppercase extension? :(
                    if os.path.exists(chkfile) or os.path.exists(chkfile_uc):
                        file_errors = verify_checksum(filepath, method)
                        if file_errors:
                            push_error(errors, filepath, file_errors)
                        else:
                            valid_weak_checksums_found += 1
                            if valid_checksums_found == 0 and os.stat(filepath).st_mtime <= strong_checksum_deadline:
                                valid_checksums_found += 1

                # Ensure we had at least one valid checksum file of any kind (for old files).
                if valid_checksums_found == 0 and os.stat(filepath).st_mtime <= strong_checksum_deadline:
                    push_error(errors, filepath, f"[CHK02] No valid checksum files (.md5, .sha1, .sha256, .sha512) found for {filename}")

                # Ensure we had at least one (valid) sha256 or sha512 file if strong checksums are enforced.
                elif valid_checksums_found == 0:
                    push_error(errors, filepath, f"[CHK02] No valid checksum files (.sha256, .sha512) found for {filename}")
                    if valid_weak_checksums_found:
                        push_error(errors, filepath, f"[CHK02] Only weak checksum files (.md5, .sha1) found for {filename}. Project MUST use sha256/sha512!")

                # Verify detached signatures
                asc_filepath = filepath + ".asc"
                if os.path.exists(asc_filepath):
                    verified = keychain.verify_file(open(asc_filepath, "rb"), data_filename=filepath)
                    if not verified.valid:
                        # Possible status values:
                        # - 'no public key' - no further checks possible
                        # - 'signature bad' - found the key, but the sig does not match
                        # - 'signature valid' - implies key problem such as expired
                        # - None - e.g. for non-empty but invalid signature (at present; this may be fixed)
                        if verified.status is None or verified.status.startswith('error '):
                            push_error(errors, filepath, f"[CHK05] The signature file {filename}.asc could not be used to verify the release artifact (corrupt sig?)")
                        elif verified.status == 'no public key':
                            push_error(errors, filepath, f"[CHK01] The signature file {filename}.asc was signed with a key not found in the project's KEYS file: {verified.key_id}")
                        elif verified.status == 'signature bad':
                            # unfortunately the current version of gnupg corrupts the key_id in this case
                            push_error(errors, filepath, f"[CHK05] The signature file {filename}.asc could not be used to verify the release artifact (corrupt sig?)")
                        elif verified.status == 'signature valid':
                            # Assume we can get the key here, else how was the signature verified?
                            key = keychain.list_keys(False, [verified.key_id])[0]
                            fp_owner = key['uids'][0] # this is always in the main key
                            if verified.key_status == 'signing key has expired':
                                if verified.key_id == key['keyid']:
                                    expires = key['expires']
                                else: # must be a subkey
                                    expires = key['subkey_info'][verified.key_id]['expires']
                                if int(expires) < int(verified.sig_timestamp):
                                    push_error(errors, filepath, f"[CHK04] Detached signature file {filename}.asc was signed by {fp_owner} ({verified.key_id}) but the key expired before the file was signed!")
                            else:
                                push_error(errors, filepath, f"[CHK04] Detached signature file {filename}.asc was signed by {fp_owner} ({verified.key_id}) but the key has status {verified.key_status}!")
                        else:
                            push_error(errors, filepath, f"[CHK05] Detached signature file {filename}.asc could not be used to verify {filename}: {verified.status}")
                else:
                    push_error(errors, filepath, f"[CHK05] No detached signature file could be found for {filename} - all artifact bundles MUST have an accompanying .asc signature file!")
    return errors


def main():
    if "--debug" in sys.argv:
        print("DEBUG MODE ENABLED. No emails will be sent.")
    if "--debug_plugin" in sys.argv:
        import logging
        logger = logging.getLogger('gnupg')
        logger.setLevel('DEBUG')
        logger.addHandler(logging.StreamHandler())
        logger.debug("Plugin debug enabled.")
    start_time = time.time()
    gpg_home = CFG["gpg_homedir"]
    if not os.path.isdir(gpg_home):
        print(f"Setting up GPG homedir in {gpg_home}")
        os.mkdir(gpg_home)
    projects = [x for x in os.listdir(CFG["dist_dir"]) if os.path.isdir(os.path.join(CFG["dist_dir"], x))]
    # Weave in incubator podlings
    projects.remove("incubator")
    inc_dir = os.path.join(CFG["dist_dir"], "incubator")
    podlings = [x for x in os.listdir(inc_dir) if os.path.isdir(os.path.join(inc_dir, x))]
    projects.extend(podlings)

    # Quick hack for only scanning certain dirs by adding the project name(s) to the command line
    x_projects = []
    for arg in sys.argv:
        if arg in projects:
            x_projects.append(arg)
    if x_projects:
        projects = x_projects
    projects = [p for p in projects if f"-{p}" not in sys.argv]  # to exclude POI: main.py -poi

    while True:
        for project in sorted(projects):
            sys.stdout.write(f"- Scanning {project}...")
            start_time_project = time.time()
            keychain = load_keys(project, project in podlings)
            errors = verify_files(project, keychain, project in podlings)
            time_taken = int(time.time() - start_time_project)
            if errors:
                sys.stdout.write(f"BAD! (scan time: {time_taken} seconds)\n")
                sys.stdout.flush()
                alert_project(project, errors)
            else:
                sys.stdout.write(f"ALL GOOD! (scan time: {time_taken} seconds)\n")
                sys.stdout.flush()
        total_time_taken = int(time.time() - start_time)
        print(f"Done scanning {len(projects)} projects in {total_time_taken} seconds.")
        if "--forever" in sys.argv:
            print(f"Sleeping for {INTERVAL} seconds.")
            time.sleep(INTERVAL)
        else:
            break


if __name__ == "__main__":
    main()

