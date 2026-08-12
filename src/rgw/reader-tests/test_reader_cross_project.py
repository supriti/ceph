#!/usr/bin/env python3
"""
Cross-project isolation test for the Keystone project-reader role, run under
BOTH rgw_keystone_implicit_tenants=true and =false.

What it proves
--------------
For each implicit-tenants mode it provisions TWO fresh Keystone projects:

  project A: owner-a (member, full control) + reader-a (project_reader only)
  project B: owner-b (member, full control)

and asserts, from reader-a's S3 credentials:

  WITHIN its own project (A):
    - ListBucket / GetObject        -> allowed   (RGW_PERM_READ)
    - GetBucketLocation             -> allowed   (RGW_PERM_READ_ACP)
    - PutObject / PutBucketAcl / CreateBucket -> denied (no WRITE / WRITE_ACP)

  ACROSS projects (B, owned by another project account):
    - ListBucket / GetObject on B's bucket -> DENIED

The cross-project denial is the interesting part, and its HTTP code reveals
what implicit_tenants actually changes:

    implicit_tenants=true   -> 404 NoSuchBucket  (B's bucket is in B's tenant,
                                                   invisible in A's namespace)
    implicit_tenants=false  -> 403 AccessDenied  (both buckets share the global
                                                   namespace; B's bucket is
                                                   visible but owner-forbidden)

Either way the reader cannot read another project -- ownership isolates it in
BOTH modes -- which is the point: the read-only cap is orthogonal to
implicit_tenants; the flag only decides bucket namespacing.

Environment (same dev container as test_project_reader.py)
  - Keystone  http://host.docker.internal:5000  (admin/password, project admin)
  - RGW       http://localhost:8000             (vstart, s3 auth use keystone)
  - config: rgw_keystone_accepted_project_reader_roles=objectstore_viewer
            rgw_keystone_accepted_roles=admin,member,_member_,objectstore_viewer

Mode switching: the script flips rgw_keystone_implicit_tenants via `ceph config
set` (the option has a live config observer, so no restart is normally needed)
and restores the original value at the end. Set CEPH="./bin/ceph" if the ceph
CLI needs your vstart wrapper, and RGW_RESTART_CMD="..." if your setup needs a
restart between modes. Fresh, mode-suffixed project names avoid reusing an
account created under the other mode's namespace.

    pip install requests boto3
    python3 test_reader_cross_project.py
"""
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

READER_ROLE = "objectstore_viewer"   # in accepted_project_reader_roles
MEMBER_ROLE = "member"               # accepted, non-reader -> full control
IMPLICIT_KEY = "rgw_keystone_implicit_tenants"

CEPH = shlex.split(os.environ.get("CEPH", "ceph"))
RGW_DAEMON = os.environ.get("RGW_DAEMON", "client.rgw.8000")
RESTART_CMD = os.environ.get("RGW_RESTART_CMD")

S = requests.Session()
passed = failed = 0
# cross-project HTTP code observed per mode, for the closing summary
cross_code = {}


def die(msg, code=2):
    print(f"\nERROR: {msg}")
    sys.exit(code)


# --------------------------------------------------------------------------
# Keystone helpers (same discipline as test_project_reader.py: ONE admin token
# for all provisioning; reuse EC2 creds so re-runs make no token POST at all).
# --------------------------------------------------------------------------
def admin_token():
    r = S.post(f"{KS}/v3/auth/tokens", json={"auth": {
        "identity": {"methods": ["password"], "password": {"user": {
            "name": ADMIN_USER, "domain": {"name": DOMAIN},
            "password": ADMIN_PASS}}},
        "scope": {"project": {"name": ADMIN_PROJECT,
                              "domain": {"name": DOMAIN}}}}})
    r.raise_for_status()
    return r.headers["X-Subject-Token"]


def find_by_name(kind, name, H):
    """Return the /v3/{kind} item named `name`, or None. Always lists the full
    (small) collection: this dev container 500s intermittently on ?name=
    filters, so we never use server-side name filtering."""
    items = S.get(f"{KS}/v3/{kind}", headers=H).json().get(kind, [])
    for it in items:
        if it["name"] == name:
            return it
    return None


def ensure(kind, name, body, H):
    """Return id of the named item, creating it if absent."""
    it = find_by_name(kind, name, H)
    if it:
        return it["id"]
    return S.post(f"{KS}/v3/{kind}", headers=H, json=body).json()[kind[:-1]]["id"]


def ensure_user(H, dom, uname, roles, role_ids, pid):
    """Ensure a user with the given roles on pid; mint/reuse one EC2 cred."""
    uid = ensure("users", uname,
                 {"user": {"name": uname, "domain_id": dom,
                           "password": "x", "enabled": True}}, H)
    for r in roles:
        S.put(f"{KS}/v3/projects/{pid}/users/{uid}/roles/{role_ids[r]}",
              headers=H)
    have = [c for c in S.get(f"{KS}/v3/users/{uid}/credentials/OS-EC2",
                             headers=H).json().get("credentials", [])
            if c.get("tenant_id") == pid]
    cred = have[0] if have else S.post(
        f"{KS}/v3/users/{uid}/credentials/OS-EC2", headers=H,
        json={"tenant_id": pid}).json()["credential"]
    return {"uid": uid, "access": cred["access"], "secret": cred["secret"]}


def s3(cred):
    return boto3.client(
        "s3", endpoint_url=RGW, aws_access_key_id=cred["access"],
        aws_secret_access_key=cred["secret"], region_name="us-east-1",
        config=Config(signature_version="s3v4", retries={"max_attempts": 1}))


# --------------------------------------------------------------------------
# assertion helper
# --------------------------------------------------------------------------
def check(label, fn, expect_ok, record_code_as=None):
    """Run fn(); PASS if allow/deny matches expect_ok. Optionally stash the
    denial HTTP code under cross_code[record_code_as] for the summary."""
    global passed, failed
    try:
        fn()
        got_ok, code = True, 200
    except ClientError as e:
        got_ok, code = False, e.response["ResponseMetadata"]["HTTPStatusCode"]
    ok = (got_ok == expect_ok)
    passed, failed = passed + ok, failed + (not ok)
    if record_code_as and not got_ok:
        cross_code[record_code_as] = code
    detail = "success" if got_ok else f"HTTP {code}"
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}  "
          f"(expected {'ok' if expect_ok else 'deny'}, got {detail})")


# --------------------------------------------------------------------------
# ceph config control
# --------------------------------------------------------------------------
def ceph_config_get(key):
    try:
        out = subprocess.run(CEPH + ["config", "get", RGW_DAEMON, key],
                             capture_output=True, text=True, timeout=30)
        return out.stdout.strip() if out.returncode == 0 else None
    except Exception:
        return None


def ceph_config_set(key, val):
    try:
        r = subprocess.run(CEPH + ["config", "set", RGW_DAEMON, key, val],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            print(f"  WARNING: `ceph config set {key} {val}` failed: "
                  f"{r.stderr.strip()}")
            print(f"           set it manually, then re-run. Proceeding with "
                  f"whatever mode is currently active.")
            return False
        return True
    except Exception as e:
        print(f"  WARNING: could not run ceph CLI ({e}); set {key}={val} "
              f"manually. Proceeding.")
        return False


# --------------------------------------------------------------------------
# one full mode run
# --------------------------------------------------------------------------
def run_mode(mode, H):
    """mode is 'true' or 'false'. H is a pre-obtained admin auth header
    (reused across modes so the whole run makes exactly one token POST --
    repeated token POSTs are what wedge this Keystone dev container)."""
    print(f"\n{'='*70}\nimplicit_tenants = {mode}\n{'='*70}")
    ceph_config_set(IMPLICIT_KEY, mode)
    if RESTART_CMD:
        print(f"  running RGW_RESTART_CMD: {RESTART_CMD}")
        subprocess.run(shlex.split(RESTART_CMD))
    time.sleep(3)  # let the config observer / restart settle

    dom = find_by_name("domains", DOMAIN, H)["id"]
    role_ids = {r: ensure("roles", r, {"role": {"name": r}}, H)
                for r in (READER_ROLE, MEMBER_ROLE)}

    # fresh, mode-suffixed projects so each account is created under THIS mode
    pA_name, pB_name = f"rdr-{mode}-a", f"rdr-{mode}-b"
    pA = ensure("projects", pA_name,
                {"project": {"name": pA_name, "domain_id": dom,
                             "enabled": True}}, H)
    pB = ensure("projects", pB_name,
                {"project": {"name": pB_name, "domain_id": dom,
                             "enabled": True}}, H)

    owner_a = s3(ensure_user(H, dom, f"owner-a-{mode}", [MEMBER_ROLE],
                             role_ids, pA))
    reader_a = s3(ensure_user(H, dom, f"reader-a-{mode}", [READER_ROLE],
                              role_ids, pA))
    owner_b = s3(ensure_user(H, dom, f"owner-b-{mode}", [MEMBER_ROLE],
                             role_ids, pB))
    print(f"  project A={pA_name} id={pA}   project B={pB_name} id={pB}")

    tag = uuid.uuid4().hex[:8]
    bkt_a = f"a-{mode}-{tag}"
    bkt_b = f"b-{mode}-{tag}"
    try:
        owner_a.create_bucket(Bucket=bkt_a)
        owner_a.put_object(Bucket=bkt_a, Key="obj", Body=b"in-A")
        owner_b.create_bucket(Bucket=bkt_b)
        owner_b.put_object(Bucket=bkt_b, Key="obj", Body=b"in-B")
        print(f"  setup: A owns {bkt_a}, B owns {bkt_b}\n")

        print("  WITHIN own project A (reader-a):")
        check("reader ListBucket (READ)",
              lambda: reader_a.list_objects_v2(Bucket=bkt_a), True)
        check("reader GetObject (READ)",
              lambda: reader_a.get_object(Bucket=bkt_a, Key="obj"), True)
        check("reader GetBucketLocation (READ_ACP)",
              lambda: reader_a.get_bucket_location(Bucket=bkt_a), True)
        check("reader PutObject (needs WRITE -> deny)",
              lambda: reader_a.put_object(Bucket=bkt_a, Key="x", Body=b"x"),
              False)
        check("reader PutBucketAcl (needs WRITE_ACP -> deny)",
              lambda: reader_a.put_bucket_acl(Bucket=bkt_a, ACL="private"),
              False)
        check("reader CreateBucket (deny)",
              lambda: reader_a.create_bucket(Bucket=f"{bkt_a}-new"), False)

        print("\n  ACROSS to project B (reader-a must NOT read B):")
        check("reader ListBucket on B's bucket (deny)",
              lambda: reader_a.list_objects_v2(Bucket=bkt_b), False,
              record_code_as=mode)
        check("reader GetObject on B's object (deny)",
              lambda: reader_a.get_object(Bucket=bkt_b, Key="obj"), False)
    finally:
        for owner, bkt in ((owner_a, bkt_a), (owner_b, bkt_b)):
            try:
                for o in owner.list_objects_v2(Bucket=bkt).get("Contents", []):
                    owner.delete_object(Bucket=bkt, Key=o["Key"])
                owner.delete_bucket(Bucket=bkt)
            except ClientError as e:
                print(f"  cleanup warning ({bkt}): {e}")
        print(f"  cleanup: removed {bkt_a}, {bkt_b}")


def main():
    original = ceph_config_get(IMPLICIT_KEY)
    print(f"original {IMPLICIT_KEY} = {original!r}")
    try:
        H = {"X-Auth-Token": admin_token()}   # one token POST for the whole run
    except Exception as e:
        die(f"Keystone auth POST failed ({e}). If the container is wedged "
            "(GET works, POST hangs), restart it on the host and retry.")
    try:
        for mode in ("true", "false"):
            run_mode(mode, H)
    finally:
        if original is not None:
            print(f"\nrestoring {IMPLICIT_KEY} = {original}")
            ceph_config_set(IMPLICIT_KEY, original)

    print(f"\n{'='*70}\nWHAT implicit_tenants CHANGED (cross-project denial code):")
    for mode in ("true", "false"):
        c = cross_code.get(mode, "?")
        why = ("bucket invisible in reader's tenant" if c == 404 else
               "bucket visible globally, owner-forbidden" if c == 403 else
               "unexpected -- mode may not have taken effect (restart RGW?)")
        print(f"  implicit_tenants={mode:<5} -> HTTP {c}  ({why})")
    print(f"{'='*70}\n----- {passed} passed, {failed} failed -----")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
