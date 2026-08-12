#!/usr/bin/env python3
"""
Live check: how does a Keystone *system_reader* behave over S3?

A "system reader" = a role in BOTH rgw_keystone_accepted_admin_roles AND
rgw_keystone_accepted_reader_roles. In *Swift* it is a global read-only
auditor: TokenEngine::get_acl_strategy grants READ across every account,
while get_creds_info excludes it from IS_ADMIN_ACCT so it cannot write.

Over *S3* that persona does NOT exist: EC2Engine::get_acl_strategy returns
nullptr, and the EC2 admin loop sets IS_ADMIN_ACCT for anything in
admin_roles. So an S3 system_reader collapses to a full admin
(IS_ADMIN_ACCT + FULL_CONTROL) -- it CAN write and is not read-only.

This script proves that over S3. It temporarily registers role
'objectstore_auditor' as a system_reader (adds it to admin_roles and
reader_roles via `ceph config set`, restored afterwards), provisions a user
holding it in project P and a separate project Q that owns a bucket, then
checks over S3:

  - system_reader PutObject in its own project  -> ALLOW  (it's admin)   [the "can it write" answer]
  - system_reader CreateBucket                  -> ALLOW  (admin)
  - system_reader ListAllMyBuckets (s3 ls)      -> observe (owner-scoped)
  - system_reader read project Q's bucket       -> observe (cross-tenant)  [the "view all" answer]

One admin-token POST for the whole run. Env matches test_project_reader.py.
    CEPH_CONF=build/ceph.conf CEPH="./build/bin/ceph" python3 src/rgw/test_system_reader.py
"""
import json
import os
import shlex
import subprocess
import sys
import time
import uuid

import requests
import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

KS = "http://host.docker.internal:5000"
RGW = "http://localhost:8000"
DOMAIN = "Default"
ADMIN_USER, ADMIN_PASS, ADMIN_PROJECT = "admin", "password", "admin"

AUDITOR = "objectstore_auditor"   # we register this as a system_reader
MEMBER = "member"
CEPH = shlex.split(os.environ.get("CEPH", "ceph"))
ASOK = os.environ.get("RGW_ASOK", "build/out/radosgw.8000.asok")

S = requests.Session()


def die(m):
    print(f"\nERROR: {m}"); sys.exit(2)


def admin_token():
    r = S.post(f"{KS}/v3/auth/tokens", json={"auth": {
        "identity": {"methods": ["password"], "password": {"user": {
            "name": ADMIN_USER, "domain": {"name": DOMAIN}, "password": ADMIN_PASS}}},
        "scope": {"project": {"name": ADMIN_PROJECT, "domain": {"name": DOMAIN}}}}})
    r.raise_for_status()
    return r.headers["X-Subject-Token"]


def find_by_name(kind, name, H):
    for it in S.get(f"{KS}/v3/{kind}", headers=H).json().get(kind, []):
        if it["name"] == name:
            return it
    return None


def ensure(kind, name, body, H):
    it = find_by_name(kind, name, H)
    return it["id"] if it else \
        S.post(f"{KS}/v3/{kind}", headers=H, json=body).json()[kind[:-1]]["id"]


def ensure_user(H, dom, uname, roles, role_ids, pid):
    uid = ensure("users", uname, {"user": {"name": uname, "domain_id": dom,
                 "password": "x", "enabled": True}}, H)
    for r in roles:
        S.put(f"{KS}/v3/projects/{pid}/users/{uid}/roles/{role_ids[r]}", headers=H)
    have = [c for c in S.get(f"{KS}/v3/users/{uid}/credentials/OS-EC2",
            headers=H).json().get("credentials", []) if c.get("tenant_id") == pid]
    cred = have[0] if have else S.post(f"{KS}/v3/users/{uid}/credentials/OS-EC2",
            headers=H, json={"tenant_id": pid}).json()["credential"]
    return {"uid": uid, "access": cred["access"], "secret": cred["secret"]}


def s3(cred):
    return boto3.client("s3", endpoint_url=RGW, aws_access_key_id=cred["access"],
        aws_secret_access_key=cred["secret"], region_name="us-east-1",
        config=Config(signature_version="s3v4", retries={"max_attempts": 1}))


def _asok(*args):
    """Talk directly to the running daemon's admin socket (runtime, immediate)."""
    return subprocess.run(CEPH + ["--admin-daemon", ASOK] + list(args),
                          capture_output=True, text=True)


def cfg_get(key):
    try:
        return json.loads(_asok("config", "get", key).stdout)[key]
    except Exception:
        return ""


def cfg_set(key, val):
    _asok("config", "set", key, val)


def observe(label, fn):
    """Run fn(); print outcome without pass/fail (for informational checks)."""
    try:
        r = fn()
        print(f"  [observe] {label} -> ALLOWED ({r})")
    except ClientError as e:
        print(f"  [observe] {label} -> DENIED HTTP "
              f"{e.response['ResponseMetadata']['HTTPStatusCode']}")


def assert_ok(label, fn, expect_ok):
    try:
        fn(); got = True; detail = "success"
    except ClientError as e:
        got = False; detail = f"HTTP {e.response['ResponseMetadata']['HTTPStatusCode']}"
    ok = got == expect_ok
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}  "
          f"(expected {'ok' if expect_ok else 'deny'}, got {detail})")


def main():
    # These role lists only take effect at daemon startup, so config is set
    # externally + the daemon restarted before we run. SKIP_CONFIG=1 tells us
    # not to touch config here.
    manage_cfg = not os.environ.get("SKIP_CONFIG")
    orig_admin = orig_reader = None
    if manage_cfg:
        orig_admin = cfg_get("rgw_keystone_accepted_admin_roles")
        orig_reader = cfg_get("rgw_keystone_accepted_reader_roles")
        new_admin = orig_admin + ("," if orig_admin else "") + AUDITOR
        cfg_set("rgw_keystone_accepted_admin_roles", new_admin)
        cfg_set("rgw_keystone_accepted_reader_roles", AUDITOR)
        print(f"set admin_roles={new_admin!r} reader_roles={AUDITOR!r} (settling)")
        time.sleep(3)
    else:
        print(f"SKIP_CONFIG: assuming {AUDITOR!r} is already a configured "
              f"system_reader (admin+reader) via a restarted daemon")

    own = oq = sysr = bP = bQ = None
    try:
        try:
            H = {"X-Auth-Token": admin_token()}
        except Exception as e:
            die(f"Keystone auth POST failed ({e}); restart the container on the host.")

        dom = find_by_name("domains", DOMAIN, H)["id"]
        role_ids = {r: ensure("roles", r, {"role": {"name": r}}, H)
                    for r in (AUDITOR, MEMBER)}
        pP = ensure("projects", "sysr-P", {"project": {"name": "sysr-P",
                    "domain_id": dom, "enabled": True}}, H)
        pQ = ensure("projects", "sysr-Q", {"project": {"name": "sysr-Q",
                    "domain_id": dom, "enabled": True}}, H)
        sysr = s3(ensure_user(H, dom, "sysreader", [AUDITOR], role_ids, pP))
        own = s3(ensure_user(H, dom, "owner-p", [MEMBER], role_ids, pP))
        oq = s3(ensure_user(H, dom, "owner-q", [MEMBER], role_ids, pQ))

        tag = uuid.uuid4().hex[:8]
        bP, bQ = f"sysp-{tag}", f"sysq-{tag}"
        own.create_bucket(Bucket=bP); own.put_object(Bucket=bP, Key="obj", Body=b"P")
        oq.create_bucket(Bucket=bQ); oq.put_object(Bucket=bQ, Key="obj", Body=b"Q")
        print(f"setup: P owns {bP}, Q owns {bQ}\n")

        print("system_reader over S3:")
        # THE "can it write" question:
        assert_ok("PutObject in own project (admin -> allowed)",
                  lambda: sysr.put_object(Bucket=bP, Key="w", Body=b"x"), True)
        assert_ok("CreateBucket (admin -> allowed)",
                  lambda: sysr.create_bucket(Bucket=f"{bP}-new"), True)
        # THE "view all buckets" question:
        buckets = [b["Name"] for b in sysr.list_buckets().get("Buckets", [])]
        print(f"  [observe] s3 ls (ListAllMyBuckets) -> {buckets}")
        observe("read project Q's bucket (cross-tenant List)",
                lambda: sysr.list_objects_v2(Bucket=bQ))
        observe("read project Q's object (cross-tenant Get)",
                lambda: sysr.get_object(Bucket=bQ, Key="obj"))
    finally:
        if manage_cfg:
            cfg_set("rgw_keystone_accepted_admin_roles", orig_admin)
            cfg_set("rgw_keystone_accepted_reader_roles", orig_reader)
            print(f"\nrestored admin_roles={orig_admin!r} reader_roles={orig_reader!r}")
        # then best-effort bucket cleanup (guarded: vars may be None)
        for c, b in ((own, bP), (oq, bQ)):
            if not (c and b):
                continue
            try:
                for o in c.list_objects_v2(Bucket=b).get("Contents", []):
                    c.delete_object(Bucket=b, Key=o["Key"])
                c.delete_bucket(Bucket=b)
            except Exception:
                pass
        if sysr and bP:
            try:
                sysr.delete_bucket(Bucket=f"{bP}-new")
            except Exception:
                pass


if __name__ == "__main__":
    main()
