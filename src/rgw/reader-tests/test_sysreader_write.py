#!/usr/bin/env python3
"""
Minimal proof: can an S3 *system_reader* write?

A system_reader = a role in BOTH rgw_keystone_accepted_admin_roles AND
rgw_keystone_accepted_reader_roles. Over S3 the read-only-auditor persona
does not exist (EC2Engine::get_acl_strategy returns nullptr) and the EC2
admin loop sets IS_ADMIN_ACCT for anything in admin_roles, so an S3
system_reader is a full admin (IS_ADMIN_ACCT + FULL_CONTROL) -> it CAN write.

This uses ONE user (fewest Keystone POSTs -- each distinct S3 user costs one
/v3/s3tokens validation POST, and this dev container wedges under POST bursts).
It assumes role 'objectstore_auditor' is already configured as a system_reader
and the radosgw restarted (those role lists only take effect at daemon start):

    ceph config set client.rgw rgw_keystone_accepted_admin_roles  admin,objectstore_auditor
    ceph config set client.rgw rgw_keystone_accepted_reader_roles objectstore_auditor
    <restart radosgw>
    python3 src/rgw/test_sysreader_write.py
"""
import sys
import uuid

import requests
import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

KS = "http://host.docker.internal:5000"
RGW = "http://localhost:8000"
DOM = "Default"
AUDITOR = "objectstore_auditor"
S = requests.Session()


def main():
    try:
        r = S.post(f"{KS}/v3/auth/tokens", timeout=8, json={"auth": {
            "identity": {"methods": ["password"], "password": {"user": {
                "name": "admin", "domain": {"name": DOM}, "password": "password"}}},
            "scope": {"project": {"name": "admin", "domain": {"name": DOM}}}}})
        r.raise_for_status()
        H = {"X-Auth-Token": r.headers["X-Subject-Token"]}
    except Exception as e:
        print(f"Keystone POST wedged ({e}); restart the container on the host.")
        sys.exit(2)

    def by(kind, name):
        for it in S.get(f"{KS}/v3/{kind}", headers=H).json().get(kind, []):
            if it["name"] == name:
                return it
        return None

    def ensure(kind, name, body):
        it = by(kind, name)
        return it["id"] if it else \
            S.post(f"{KS}/v3/{kind}", headers=H, json=body).json()[kind[:-1]]["id"]

    dom = by("domains", DOM)["id"]
    rid = ensure("roles", AUDITOR, {"role": {"name": AUDITOR}})
    pid = ensure("projects", "sysr-W", {"project": {"name": "sysr-W",
                 "domain_id": dom, "enabled": True}})
    uid = ensure("users", "syswriter", {"user": {"name": "syswriter",
                 "domain_id": dom, "password": "x", "enabled": True}})
    S.put(f"{KS}/v3/projects/{pid}/users/{uid}/roles/{rid}", headers=H)
    have = [c for c in S.get(f"{KS}/v3/users/{uid}/credentials/OS-EC2",
            headers=H).json().get("credentials", []) if c.get("tenant_id") == pid]
    cred = have[0] if have else S.post(f"{KS}/v3/users/{uid}/credentials/OS-EC2",
            headers=H, json={"tenant_id": pid}).json()["credential"]

    c = boto3.client("s3", endpoint_url=RGW, aws_access_key_id=cred["access"],
        aws_secret_access_key=cred["secret"], region_name="us-east-1",
        config=Config(signature_version="s3v4", retries={"max_attempts": 1}))
    b = f"syswrite-{uuid.uuid4().hex[:8]}"

    def check(label, fn):
        try:
            fn()
            print(f"  [{label}] -> ALLOWED  (system_reader CAN write)")
        except ClientError as e:
            code = e.response["ResponseMetadata"]["HTTPStatusCode"]
            print(f"  [{label}] -> DENIED HTTP {code}")

    print(f"S3 system_reader ({AUDITOR} = admin+reader) write test, one user:")
    check("CreateBucket", lambda: c.create_bucket(Bucket=b))
    check("PutObject", lambda: c.put_object(Bucket=b, Key="o", Body=b"x"))
    try:
        for o in c.list_objects_v2(Bucket=b).get("Contents", []):
            c.delete_object(Bucket=b, Key=o["Key"])
        c.delete_bucket(Bucket=b)
    except ClientError:
        pass


if __name__ == "__main__":
    main()
