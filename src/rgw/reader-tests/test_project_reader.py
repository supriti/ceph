#!/usr/bin/env python3
"""
Integration test for the Keystone project-reader role (git HEAD behaviour).

Pins exactly three contracts, all derived from the code at HEAD:

  1. READ-ONLY FLOOR. A Keystone user whose only accepted role is a
     project-reader role (rgw_keystone_accepted_project_reader_roles) is
     capped to RGW_PERM_READ. It can ListBucket and GetObject across its
     project (implicit_tenants=true -> every project user shares one RGW
     owner, so owner-scoped reads cover every project bucket), but PutObject
     is denied. Source: rgw_auth_keystone.cc sets perm_mask=RGW_PERM_READ via
     TokenEnvelope::is_project_reader_only(); the write dies on the no-policy
     ACL fallback in verify_bucket_permission_no_policy ((perm & perm_mask)).

  2. POLICY OVERRIDE (scoped). A bucket policy naming the reader by
     keystone:userid for s3:PutObject lets that reader write to THAT bucket.
     Source: verify_bucket_permission evaluates the policy first; an Effect
     Allow returns true before perm_mask is ever consulted. The override is
     scoped to the named user only -- another reader not named in the policy
     still gets 403 on the same bucket.

  3. A RANDOM ROLE GRANTS THE READER NOTHING. A role that is in no accepted
     list is ignored (fail-closed): a reader that also holds such a role is
     still capped to read-only. By contrast, an accepted non-reader role
     (member) lifts the cap to full control. Source: is_project_reader_only()
     only inspects is_accepted roles; unaccepted roles never set is_accepted.

Environment (already up in this dev container):
  - Keystone  http://host.docker.internal:5000  (admin/password, project admin)
  - RGW       http://localhost:8000             (vstart, s3 auth use keystone)
  - config: rgw_keystone_accepted_project_reader_roles=objectstore_viewer
            rgw_keystone_accepted_roles=admin,member,_member_,objectstore_viewer
            rgw_keystone_implicit_tenants=true

Self-provisioning and idempotent. Uses ONE admin token for all provisioning
AND EC2 minting (repeated *token* POSTs are what wedge this Keystone dev
container), reusing an existing EC2 credential when the user already has one
so re-runs issue no token POST at all. Cleans up the bucket it creates.

    pip install requests boto3
    python3 test_project_reader.py
"""
import sys
import uuid

import requests
import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

KS = "http://host.docker.internal:5000"
RGW = "http://localhost:8000"
DOMAIN = "Default"
ADMIN_USER, ADMIN_PASS, ADMIN_PROJECT = "admin", "password", "admin"

PROJECT = "rgw-policy-test"
READER_ROLE = "objectstore_viewer"   # in accepted_project_reader_roles
MEMBER_ROLE = "member"               # accepted, non-reader -> full control
RANDOM_ROLE = "zz_no_access"         # in NO accepted list -> ignored

# user -> roles on the project
USERS = {
    "reader-only":   ("readerpass", [READER_ROLE]),
    "reader-random": ("randompass", [READER_ROLE, RANDOM_ROLE]),
    "member-writer": ("writerpass", [MEMBER_ROLE]),
}

S = requests.Session()
passed = failed = 0


def die(msg, code=2):
    print(f"\nERROR: {msg}")
    sys.exit(code)


def admin_token():
    r = S.post(f"{KS}/v3/auth/tokens", json={"auth": {
        "identity": {"methods": ["password"], "password": {"user": {
            "name": ADMIN_USER, "domain": {"name": DOMAIN},
            "password": ADMIN_PASS}}},
        "scope": {"project": {"name": ADMIN_PROJECT,
                              "domain": {"name": DOMAIN}}}}})
    r.raise_for_status()
    return r.headers["X-Subject-Token"]


def ensure(kind, name, body, H, find_qs):
    """GET by name; create if absent. Return id."""
    for it in S.get(f"{KS}/v3/{kind}?{find_qs}", headers=H).json()[kind]:
        if it["name"] == name:
            return it["id"]
    return S.post(f"{KS}/v3/{kind}", headers=H,
                  json=body).json()[kind[:-1]]["id"]


def provision():
    """Idempotently ensure project/roles/users; mint one fresh EC2 key each.
    Returns {uname: {"uid", "access", "secret"}} and the project id."""
    try:
        H = {"X-Auth-Token": admin_token()}
    except Exception as e:
        die(f"Keystone auth POST failed ({e}). If this container is wedged, "
            "restart it on the host and retry.")

    dom = S.get(f"{KS}/v3/domains?name={DOMAIN}",
                headers=H).json()["domains"][0]["id"]

    role_ids = {}
    for r in (READER_ROLE, MEMBER_ROLE, RANDOM_ROLE):
        role_ids[r] = ensure("roles", r, {"role": {"name": r}}, H, f"name={r}")

    pid = ensure("projects", PROJECT,
                 {"project": {"name": PROJECT, "domain_id": dom,
                              "enabled": True}},
                 H, f"name={PROJECT}&domain_id={dom}")

    out = {}
    for uname, (pw, roles) in USERS.items():
        uid = ensure("users", uname,
                     {"user": {"name": uname, "domain_id": dom,
                               "password": pw, "enabled": True}},
                     H, f"name={uname}&domain_id={dom}")
        for r in roles:
            S.put(f"{KS}/v3/projects/{pid}/users/{uid}/roles/{role_ids[r]}",
                  headers=H)
        # Reuse an existing EC2 credential (Keystone returns the secret on
        # GET); otherwise mint one with the admin token. Using the admin
        # token avoids per-user token POSTs -- those are what wedge this
        # Keystone container -- so re-runs make no token POST at all.
        have = [c for c in S.get(f"{KS}/v3/users/{uid}/credentials/OS-EC2",
                                 headers=H).json().get("credentials", [])
                if c.get("tenant_id") == pid]
        cred = have[0] if have else S.post(
            f"{KS}/v3/users/{uid}/credentials/OS-EC2", headers=H,
            json={"tenant_id": pid}).json()["credential"]
        out[uname] = {"uid": uid, "access": cred["access"],
                      "secret": cred["secret"]}
    return pid, out


def s3(access, secret):
    return boto3.client(
        "s3", endpoint_url=RGW, aws_access_key_id=access,
        aws_secret_access_key=secret, region_name="us-east-1",
        config=Config(signature_version="s3v4",
                      retries={"max_attempts": 1}))


def check(label, fn, expect_ok):
    global passed, failed
    try:
        fn()
        got_ok, detail = True, "success"
    except ClientError as e:
        code = e.response["ResponseMetadata"]["HTTPStatusCode"]
        got_ok, detail = False, f"HTTP {code}"
    ok = (got_ok == expect_ok)
    passed, failed = passed + ok, failed + (not ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}  "
          f"(expected {'ok' if expect_ok else 'deny'}, got {detail})")


def main():
    print("provisioning Keystone fixtures (single admin token)...")
    pid, u = provision()
    reader = s3(u["reader-only"]["access"],   u["reader-only"]["secret"])
    randr  = s3(u["reader-random"]["access"], u["reader-random"]["secret"])
    member = s3(u["member-writer"]["access"], u["member-writer"]["secret"])
    reader_uid = u["reader-only"]["uid"]
    print(f"  project {PROJECT} id={pid}")
    print(f"  reader-only uid={reader_uid}\n")

    bucket = f"pr-test-{uuid.uuid4().hex[:8]}"
    try:
        # member (full control, owns the shared project account) sets up
        member.create_bucket(Bucket=bucket)
        member.put_object(Bucket=bucket, Key="seed", Body=b"hello")
        print(f"setup: member-writer created {bucket} + seed\n")

        print("[1] READ-ONLY FLOOR (reader-only, no policy)")
        check("reader ListBucket", lambda: reader.list_objects_v2(Bucket=bucket), True)
        check("reader GetObject seed", lambda: reader.get_object(Bucket=bucket, Key="seed"), True)
        check("reader PutObject", lambda: reader.put_object(Bucket=bucket, Key="r1", Body=b"x"), False)
        check("reader CreateBucket", lambda: reader.create_bucket(Bucket=f"{bucket}-r"), False)

        print("\n[3] RANDOM ROLE GRANTS NOTHING / ACCEPTED ROLE OVERRIDES")
        check("reader+random GetObject (still reads)", lambda: randr.get_object(Bucket=bucket, Key="seed"), True)
        check("reader+random PutObject (random ignored -> still capped)",
              lambda: randr.put_object(Bucket=bucket, Key="rr1", Body=b"x"), False)
        check("member PutObject (accepted role -> full control)",
              lambda: member.put_object(Bucket=bucket, Key="m1", Body=b"x"), True)

        # attach a policy that names ONLY reader-only for PutObject
        policy = ('{"Version":"2012-10-17","Statement":[{'
                  '"Sid":"ElevateReader","Effect":"Allow","Principal":"*",'
                  '"Action":["s3:PutObject"],'
                  f'"Resource":["arn:aws:s3:::{bucket}/*"],'
                  '"Condition":{"StringEquals":'
                  f'{{"keystone:userid":"{reader_uid}"}}}}}}]}}')
        member.put_bucket_policy(Bucket=bucket, Policy=policy)
        print(f"\nsetup: attached policy elevating {reader_uid} for PutObject\n")

        print("[2] POLICY OVERRIDE (scoped to the named reader)")
        check("reader PutObject (policy Allow -> writes)",
              lambda: reader.put_object(Bucket=bucket, Key="r2", Body=b"granted"), True)
        check("reader+random PutObject (not named -> still 403)",
              lambda: randr.put_object(Bucket=bucket, Key="rr2", Body=b"x"), False)
    finally:
        try:
            member.delete_bucket_policy(Bucket=bucket)
        except ClientError:
            pass
        try:
            for o in member.list_objects_v2(Bucket=bucket).get("Contents", []):
                member.delete_object(Bucket=bucket, Key=o["Key"])
            member.delete_bucket(Bucket=bucket)
            print(f"\ncleanup: removed {bucket}")
        except ClientError as e:
            print(f"\ncleanup warning: {e}")

    print(f"\n----- {passed} passed, {failed} failed -----")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
