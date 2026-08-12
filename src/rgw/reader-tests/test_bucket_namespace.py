#!/usr/bin/env python3
"""
Verify what implicit_tenants does to the bucket NAME space.

  implicit_tenants=true  -> two DIFFERENT Keystone projects can BOTH create a
                            bucket with the SAME name (per-tenant namespace).
  implicit_tenants=false -> bucket names are GLOBAL: the second project CANNOT
                            reuse a name the first already took.

For each mode it makes two fresh, mode-suffixed projects (A and B), a member
user in each, then has A create a bucket and B try the SAME name:
  true  -> B succeeds (separate namespaces)
  false -> B fails with BucketAlreadyExists (shared global namespace)

implicit_tenants IS a live config observer (unlike the role lists), so we flip
it at runtime with `ceph config set` -- no restart. Fresh project names per
mode so each account is created under the mode being tested. One admin-token
POST for the whole run.

    CEPH_CONF=build/ceph.conf CEPH="./build/bin/ceph" RGW_DAEMON=client.rgw.8000 \
      python3 src/rgw/test_bucket_namespace.py
"""
import json
import os
import shlex
import subprocess
import sys
import time

import requests
import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

KS = "http://host.docker.internal:5000"
RGW = "http://localhost:8000"
DOMAIN = "Default"
ADMIN_USER, ADMIN_PASS, ADMIN_PROJECT = "admin", "password", "admin"
MEMBER = "member"
IMPLICIT_KEY = "rgw_keystone_implicit_tenants"
CEPH = shlex.split(os.environ.get("CEPH", "ceph"))
RGW_DAEMON = os.environ.get("RGW_DAEMON", "client.rgw.8000")
S = requests.Session()
passed = failed = 0


def die(m):
    print(m); sys.exit(2)


def admin_token():
    r = S.post(f"{KS}/v3/auth/tokens", timeout=8, json={"auth": {
        "identity": {"methods": ["password"], "password": {"user": {
            "name": ADMIN_USER, "domain": {"name": DOMAIN}, "password": ADMIN_PASS}}},
        "scope": {"project": {"name": ADMIN_PROJECT, "domain": {"name": DOMAIN}}}}})
    r.raise_for_status()
    return r.headers["X-Subject-Token"]


def by(kind, name, H):
    for it in S.get(f"{KS}/v3/{kind}", headers=H).json().get(kind, []):
        if it["name"] == name:
            return it
    return None


def ensure(kind, name, body, H):
    it = by(kind, name, H)
    return it["id"] if it else \
        S.post(f"{KS}/v3/{kind}", headers=H, json=body).json()[kind[:-1]]["id"]


def ensure_member(H, dom, uname, pid, rid):
    uid = ensure("users", uname, {"user": {"name": uname, "domain_id": dom,
                 "password": "x", "enabled": True}}, H)
    S.put(f"{KS}/v3/projects/{pid}/users/{uid}/roles/{rid}", headers=H)
    have = [c for c in S.get(f"{KS}/v3/users/{uid}/credentials/OS-EC2",
            headers=H).json().get("credentials", []) if c.get("tenant_id") == pid]
    cred = have[0] if have else S.post(f"{KS}/v3/users/{uid}/credentials/OS-EC2",
            headers=H, json={"tenant_id": pid}).json()["credential"]
    return boto3.client("s3", endpoint_url=RGW, aws_access_key_id=cred["access"],
        aws_secret_access_key=cred["secret"], region_name="us-east-1",
        config=Config(signature_version="s3v4", retries={"max_attempts": 1}))


def cfg_set(key, val):
    subprocess.run(CEPH + ["config", "set", RGW_DAEMON, key, val],
                   capture_output=True, text=True)


def cfg_get(key):
    try:
        return json.loads(subprocess.run(CEPH + ["config", "get", RGW_DAEMON, key],
               capture_output=True, text=True).stdout)[key]
    except Exception:
        return None


def check(label, fn, expect_ok):
    global passed, failed
    try:
        fn(); got, detail = True, "success"
    except ClientError as e:
        code = e.response["Error"].get("Code", "?")
        http = e.response["ResponseMetadata"]["HTTPStatusCode"]
        got, detail = False, f"{code} (HTTP {http})"
    ok = got == expect_ok
    passed, failed = passed + ok, failed + (not ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label} "
          f"(expected {'ok' if expect_ok else 'deny'}, got {detail})")


def run_mode(mode, H, dom, rid):
    print(f"\n{'='*68}\nimplicit_tenants = {mode}\n{'='*68}")
    cfg_set(IMPLICIT_KEY, mode)
    time.sleep(3)

    pA = ensure("projects", f"nm-{mode}-a", {"project": {"name": f"nm-{mode}-a",
                "domain_id": dom, "enabled": True}}, H)
    pB = ensure("projects", f"nm-{mode}-b", {"project": {"name": f"nm-{mode}-b",
                "domain_id": dom, "enabled": True}}, H)
    A = ensure_member(H, dom, f"nm-{mode}-ua", pA, rid)
    B = ensure_member(H, dom, f"nm-{mode}-ub", pB, rid)

    name = f"shared-{mode}"          # SAME name attempted by both projects
    print(f"  project A={pA[:8]}  project B={pB[:8]}  bucket name={name!r}\n")
    try:
        check(f"project A creates {name!r}",
              lambda: A.create_bucket(Bucket=name), True)
        # the key assertion: can B reuse the same name?
        check(f"project B creates SAME name {name!r}",
              lambda: B.create_bucket(Bucket=name),
              True if mode == "true" else False)
    finally:
        for c in (A, B):
            try:
                c.delete_bucket(Bucket=name)
            except ClientError:
                pass


def main():
    orig = cfg_get(IMPLICIT_KEY)
    print(f"original {IMPLICIT_KEY} = {orig!r}")
    try:
        H = {"X-Auth-Token": admin_token()}
    except Exception as e:
        die(f"Keystone POST wedged ({e}); restart the container on the host.")
    dom = by("domains", DOMAIN, H)["id"]
    rid = ensure("roles", MEMBER, {"role": {"name": MEMBER}}, H)
    try:
        for mode in ("true", "false"):
            run_mode(mode, H, dom, rid)
    finally:
        if orig:
            cfg_set(IMPLICIT_KEY, orig)
            print(f"\nrestored {IMPLICIT_KEY} = {orig}")
    print(f"\n----- {passed} passed, {failed} failed -----")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
