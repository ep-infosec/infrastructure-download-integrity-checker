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

"""Download Integrity Checker Test Harness"""

from pprint import pprint
import os
import sys
import yaml

# Expected errors
RESULTS = yaml.safe_load(open("./results.yaml"))
total_errors = 0
def alert_project_intercept(project: str, errors: dict):
    global total_errors
    if project not in RESULTS:
        print(f"Not expecting errors for {project}")
        pprint(errors)
        total_errors += 1
        return

    results = RESULTS[project]
    for filepath in errors:
        actuals = set(errors[filepath])
        if filepath not in results:
            print(f"Not expecting any errors for {project}: {filepath}; saw {actuals}")
            total_errors += 1
        else:
            expecteds = set(results.pop(filepath)) # assume all OK
            if actuals != expecteds:
                unexpecteds = actuals - expecteds
                unseen = expecteds - actuals
                print(f"Unexpected error for {project}: {filepath} - {unexpecteds}")
                total_errors += len(unexpecteds)
                results[filepath] = unseen

if __name__ == "__main__":
    # Ensure old modification date for testing
    os.utime('dist/httpd/test_oldoldext.zip', (0, 0))
    # Hack to intercept alert messages
    sys.path.insert(0, '..')
    import main
    main.alert_project = alert_project_intercept
    main.main()
    # any errors unseen?
    for project in RESULTS:
        for file in RESULTS[project]:
            print(f"Expected error for {project} {file} : {RESULTS[project][file]}")
            total_errors += 1
    print(f"Found {total_errors} errors")
    if total_errors:
        sys.exit(1)