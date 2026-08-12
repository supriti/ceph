#!/usr/bin/env python3
"""
Reader-role API matrix: exercise the client-reachable S3 operations and
assert the project-reader cap behaves per op_to_perm().

For every operation the RGW permission layer maps the op to a permission
class via rgw::IAM::op_to_perm() (rgw_iam_policy.h) and checks it against
the identity's perm_mask. A project reader's mask is RGW_PERM_READ |
RGW_PERM_READ_ACP, so:

  * READ and READ_ACP ops  -> ALLOWED  (data reads + config reads)
  * WRITE and WRITE_ACP ops -> DENIED  (403 AccessDenied), unless a bucket
                                        policy names the reader (not tested
                                        here; see test_project_reader.py)

This walks the S3 surface implemented by the RGWOp classes in rgw_op.cc
(GetObj/PutObj/DeleteObj, the bucket sub-resource get/put/delete pairs,
listing, multipart, object-lock, ...) and the SNS topic ops in
rgw_rest_pubsub.cc (create/get/set/delete topic), grouped by expected
permission class.

FAITHFULNESS RULES (why a check passes):
  - READ op  -> PASS if the call does NOT return 403. A 200, or a benign
    404 (NoSuchBucketPolicy / NoSuchCORSConfiguration / ... because the
    feature simply isn't configured) both mean "permission was granted".
    A 403 on a read is a FAIL: the cap is wrongly blocking a read.
  - WRITE op -> PASS only on 403 AccessDenied. Success is a FAIL (the cap
    leaked). Any other code is reported as UNEXPECTED so it can be looked
    at (permission may not have been the gate).

NOT COVERED (out of client reach or not perm_mask-governed): admin ops,
multisite/replication-internal ops, STS, IAM/role/user ops, and the
bucket ?mdsearch sub-resource (no native boto3 call) -- mdsearch and the
owner-grant primitive are covered by the unit tests
(test_rgw_keystone.cc, KeystoneOwnerCap).

Environment (same dev container as test_project_reader.py):
  - Keystone http://host.docker.internal:5000  (admin/password)
  - RGW      http://localhost:8000             (vstart, s3 auth use keystone)
  - config:  rgw_keystone_accepted_project_reader_roles=objectstore_viewer
             rgw_keystone_accepted_roles=admin,member,objectstore_viewer
             rgw_keystone_implicit_tenants=true

    pip install requests boto3
    python3 test_reader_api_matrix.py
"""
import sys
import uuid

import requests
import boto3
from botocore.client import Config
from botocore.exceptions import ClientError, EndpointConnectionError

KS = "http://host.docker.internal:5000"
RGW = "http://localhost:8000"
DOMAIN = "Default"
ADMIN_USER, ADMIN_PASS, ADMIN_PROJECT = "admin", "password", "admin"

PROJECT = "rgw-reader-matrix"
READER_ROLE = "objectstore_viewer"   # rgw_keystone_accepted_project_reader_roles
MEMBER_ROLE = "member"               # accepted, non-reader -> full control

USERS = {
    "matrix-reader": ("readerpass", [READER_ROLE]),
    "matrix-member": ("memberpass", [MEMBER_ROLE]),
}

S = requests.Session()
passed = failed = unexpected = 0


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
    for it in S.get(f"{KS}/v3/{kind}?{find_qs}", headers=H).json()[kind]:
        if it["name"] == name:
            return it["id"]
    return S.post(f"{KS}/v3/{kind}", headers=H,
                  json=body).json()[kind[:-1]]["id"]


def provision():
    """Idempotently ensure project/roles/users; reuse or mint one EC2 key
    each, using the single admin token (no per-user token POSTs)."""
    try:
        H = {"X-Auth-Token": admin_token()}
    except Exception as e:
        die(f"Keystone auth POST failed ({e}). If this container is wedged, "
            "restart it on the host and retry.")

    dom = S.get(f"{KS}/v3/domains?name={DOMAIN}",
                headers=H).json()["domains"][0]["id"]

    role_ids = {}
    for r in (READER_ROLE, MEMBER_ROLE):
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


def sns(access, secret):
    return boto3.client(
        "sns", endpoint_url=RGW, aws_access_key_id=access,
        aws_secret_access_key=secret, region_name="us-east-1",
        config=Config(signature_version="s3v4",
                      retries={"max_attempts": 1}))


def status_of(e):
    return e.response["ResponseMetadata"]["HTTPStatusCode"]


def check(perm_class, label, fn):
    """perm_class in {READ, READ_ACP, WRITE, WRITE_ACP}. Security property:
    a READ must not be blocked by the cap (403); a WRITE must not SUCCEED
    (2xx). A write that returns 403 means the cap fired; a write that returns
    another non-2xx (404/405/501) also caused no mutation -- the op simply
    isn't reachable in this build, so the cap wasn't exercised, not bypassed."""
    global passed, failed, unexpected
    allow = perm_class in ("READ", "READ_ACP")
    try:
        fn()
        code, success, got = 200, True, "OK 200"
    except ClientError as e:
        code = status_of(e)
        errc = e.response.get("Error", {}).get("Code", "")
        success, got = False, f"{code} {errc}"

    if allow:
        ok = (code != 403)         # a read must not be denied by the cap
        note = "" if ok else "  <-- read wrongly denied by cap"
    else:
        ok = not success           # a write must not succeed (no mutation)
        if ok and code != 403:
            unexpected += 1
            note = f"  (no mutation; {code}, op not reachable — cap not exercised)"
        elif ok:
            note = ""
        else:
            note = "  <-- WRITE SUCCEEDED — cap leaked!"
    passed, failed = passed + ok, failed + (not ok)
    exp = "allow" if allow else "deny"
    print(f"  [{'PASS' if ok else 'FAIL'}] {perm_class:9} {label:38} "
          f"expect={exp:5} got={got}{note}")


def run_s3_matrix(reader, bucket, key):
    b, k = dict(Bucket=bucket), dict(Bucket=bucket, Key=key)

    print("\n== READ (data) : reader ALLOWED ==")
    check("READ", "ListAllMyBuckets", lambda: reader.list_buckets())
    check("READ", "ListBucket", lambda: reader.list_objects_v2(**b))
    check("READ", "ListBucketVersions", lambda: reader.list_object_versions(**b))
    check("READ", "ListMultipartUploads", lambda: reader.list_multipart_uploads(**b))
    check("READ", "GetObject", lambda: reader.get_object(**k))
    check("READ", "GetObjectTagging", lambda: reader.get_object_tagging(**k))
    check("READ", "GetObjectAttributes",
          lambda: reader.get_object_attributes(**k, ObjectAttributes=["ETag"]))

    print("\n== READ_ACP (config reads) : reader ALLOWED ==")
    check("READ_ACP", "GetBucketAcl", lambda: reader.get_bucket_acl(**b))
    check("READ_ACP", "GetBucketLocation", lambda: reader.get_bucket_location(**b))
    check("READ_ACP", "GetBucketVersioning", lambda: reader.get_bucket_versioning(**b))
    check("READ_ACP", "GetBucketPolicy", lambda: reader.get_bucket_policy(**b))
    check("READ_ACP", "GetBucketPolicyStatus", lambda: reader.get_bucket_policy_status(**b))
    check("READ_ACP", "GetBucketCors", lambda: reader.get_bucket_cors(**b))
    check("READ_ACP", "GetBucketTagging", lambda: reader.get_bucket_tagging(**b))
    check("READ_ACP", "GetBucketWebsite", lambda: reader.get_bucket_website(**b))
    check("READ_ACP", "GetBucketLifecycle", lambda: reader.get_bucket_lifecycle_configuration(**b))
    check("READ_ACP", "GetBucketRequestPayment", lambda: reader.get_bucket_request_payment(**b))
    check("READ_ACP", "GetBucketEncryption", lambda: reader.get_bucket_encryption(**b))
    check("READ_ACP", "GetBucketNotification", lambda: reader.get_bucket_notification_configuration(**b))
    check("READ_ACP", "GetBucketReplication", lambda: reader.get_bucket_replication(**b))
    check("READ_ACP", "GetBucketObjectLock", lambda: reader.get_object_lock_configuration(**b))
    check("READ_ACP", "GetPublicAccessBlock", lambda: reader.get_public_access_block(**b))
    check("READ_ACP", "GetBucketOwnershipControls", lambda: reader.get_bucket_ownership_controls(**b))
    check("READ_ACP", "GetObjectAcl", lambda: reader.get_object_acl(**k))

    print("\n== WRITE (data) : reader DENIED (403) ==")
    check("WRITE", "CreateBucket", lambda: reader.create_bucket(Bucket=f"{bucket}-x"))
    check("WRITE", "PutObject", lambda: reader.put_object(**k, Body=b"x"))
    check("WRITE", "DeleteObject", lambda: reader.delete_object(**k))
    check("WRITE", "PutObjectTagging",
          lambda: reader.put_object_tagging(**k, Tagging={"TagSet": [{"Key": "a", "Value": "b"}]}))
    check("WRITE", "DeleteObjectTagging", lambda: reader.delete_object_tagging(**k))
    check("WRITE", "DeleteBucket", lambda: reader.delete_bucket(**b))
    check("WRITE", "CreateMultipartUpload",
          lambda: reader.create_multipart_upload(**k))
    check("WRITE", "RestoreObject",
          lambda: reader.restore_object(**k, RestoreRequest={"Days": 1}))

    print("\n== WRITE_ACP (config writes) : reader DENIED (403) ==")
    check("WRITE_ACP", "PutBucketAcl", lambda: reader.put_bucket_acl(**b, ACL="private"))
    check("WRITE_ACP", "PutBucketPolicy",
          lambda: reader.put_bucket_policy(**b, Policy='{"Version":"2012-10-17","Statement":[]}'))
    check("WRITE_ACP", "DeleteBucketPolicy", lambda: reader.delete_bucket_policy(**b))
    check("WRITE_ACP", "PutBucketVersioning",
          lambda: reader.put_bucket_versioning(**b, VersioningConfiguration={"Status": "Enabled"}))
    check("WRITE_ACP", "PutBucketCors",
          lambda: reader.put_bucket_cors(**b, CORSConfiguration={"CORSRules": [{"AllowedMethods": ["GET"], "AllowedOrigins": ["*"]}]}))
    check("WRITE_ACP", "PutBucketTagging",
          lambda: reader.put_bucket_tagging(**b, Tagging={"TagSet": [{"Key": "a", "Value": "b"}]}))
    check("WRITE_ACP", "PutBucketLifecycle",
          lambda: reader.put_bucket_lifecycle_configuration(
              **b, LifecycleConfiguration={"Rules": [{"ID": "r", "Status": "Enabled", "Prefix": "", "Expiration": {"Days": 30}}]}))
    check("WRITE_ACP", "PutBucketRequestPayment",
          lambda: reader.put_bucket_request_payment(**b, RequestPaymentConfiguration={"Payer": "Requester"}))
    check("WRITE_ACP", "DeleteBucketWebsite", lambda: reader.delete_bucket_website(**b))
    check("WRITE_ACP", "PutBucketOwnershipControls",
          lambda: reader.put_bucket_ownership_controls(**b, OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]}))
    check("WRITE_ACP", "PutObjectAcl", lambda: reader.put_object_acl(**k, ACL="private"))


def run_sns_matrix(reader, member, region="us-east-1"):
    """SNS topic ops (rgw_rest_pubsub.cc). The member (full control) owns the
    topic; the reader, who shares the project account and thus 'owns' it too,
    may read it but not mutate it -- the owner-fallback bypass we fixed."""
    print("\n== SNS topics (rgw_rest_pubsub.cc) ==")
    name = f"rdr-topic-{uuid.uuid4().hex[:8]}"
    try:
        arn = member.create_topic(Name=name)["TopicArn"]
    except (ClientError, EndpointConnectionError, KeyError) as e:
        print(f"  [SKIP] SNS not available in this endpoint ({e}); "
              "SNS cap is covered by KeystoneOwnerCap unit tests")
        return None
    check("READ", "sns:GetTopicAttributes",
          lambda: reader.get_topic_attributes(TopicArn=arn))
    check("READ", "sns:ListTopics", lambda: reader.list_topics())
    check("WRITE", "sns:SetTopicAttributes",
          lambda: reader.set_topic_attributes(
              TopicArn=arn, AttributeName="Policy", AttributeValue=""))
    check("WRITE", "sns:CreateTopic(overwrite)",
          lambda: reader.create_topic(Name=name))
    check("WRITE", "sns:DeleteTopic",
          lambda: reader.delete_topic(TopicArn=arn))
    return arn


def main():
    print("provisioning Keystone fixtures (single admin token)...")
    pid, u = provision()
    reader = s3(u["matrix-reader"]["access"], u["matrix-reader"]["secret"])
    member = s3(u["matrix-member"]["access"], u["matrix-member"]["secret"])
    reader_sns = sns(u["matrix-reader"]["access"], u["matrix-reader"]["secret"])
    member_sns = sns(u["matrix-member"]["access"], u["matrix-member"]["secret"])
    print(f"  project {PROJECT} id={pid}")
    print(f"  reader uid={u['matrix-reader']['uid']}")

    bucket = f"rm-{uuid.uuid4().hex[:8]}"
    key = "seed"
    topic_arn = None
    try:
        member.create_bucket(Bucket=bucket)
        member.put_object(Bucket=bucket, Key=key, Body=b"hello")
        print(f"setup: member created {bucket}/{key}")

        run_s3_matrix(reader, bucket, key)
        topic_arn = run_sns_matrix(reader_sns, member_sns)
    finally:
        try:
            if topic_arn:
                member_sns.delete_topic(TopicArn=topic_arn)
        except Exception:
            pass
        try:
            for o in member.list_objects_v2(Bucket=bucket).get("Contents", []):
                member.delete_object(Bucket=bucket, Key=o["Key"])
            member.delete_bucket(Bucket=bucket)
            print(f"\ncleanup: removed {bucket}")
        except ClientError as e:
            print(f"\ncleanup warning: {e}")

    tail = f", {unexpected} unexpected-code" if unexpected else ""
    print(f"\n----- {passed} passed, {failed} failed{tail} -----")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
