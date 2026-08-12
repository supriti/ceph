#!/usr/bin/env python3
"""
Bucket-policy override, scoped to one bucket.

A project reader is read-only by default (perm_mask cap). But
verify_bucket_permission() evaluates the bucket policy BEFORE the cap, so
an explicit Allow naming the reader lifts the cap -- for THAT bucket only.

This proves both halves at once:
  bucket A  has a policy allowing the reader's keystone:userid to PutObject
            -> reader CAN write to A          (policy Allow wins)
  bucket B  has no policy
            -> reader CANNOT write to B (403)  (cap still applies)

Reuses the fixtures test_reader_api_matrix.py provisions (project
rgw-reader-matrix, users matrix-reader / matrix-member), so just run:

    python3 src/rgw/test_reader_bucket_policy.py
"""
import sys
import uuid

from botocore.exceptions import ClientError

# same dir on sys.path when run as a script -> reuse the matrix helpers
from test_reader_api_matrix import provision, s3

passed = failed = 0


def check(label, fn, expect):
    """expect: 'allow' -> must succeed (2xx); 'deny' -> must be 403."""
    global passed, failed
    try:
        fn()
        code, got = 200, "OK 200"
    except ClientError as e:
        code = e.response["ResponseMetadata"]["HTTPStatusCode"]
        got = f"{code} {e.response.get('Error', {}).get('Code', '')}"
    ok = (code != 403) if expect == "allow" else (code == 403)
    passed, failed = passed + ok, failed + (not ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label:42} expect={expect:5} got={got}")


def main():
    print("provisioning (reusing matrix fixtures)...")
    pid, u = provision()
    reader_uid = u["matrix-reader"]["uid"]
    reader = s3(u["matrix-reader"]["access"], u["matrix-reader"]["secret"])
    member = s3(u["matrix-member"]["access"], u["matrix-member"]["secret"])
    print(f"  reader uid={reader_uid}")

    A = f"pol-a-{uuid.uuid4().hex[:8]}"   # gets the elevating policy
    B = f"pol-b-{uuid.uuid4().hex[:8]}"   # no policy
    try:
        member.create_bucket(Bucket=A)
        member.create_bucket(Bucket=B)
        member.put_object(Bucket=A, Key="seed", Body=b"x")
        member.put_object(Bucket=B, Key="seed", Body=b"x")

        # allow ONLY this reader (by keystone:userid) to PutObject on A
        policy = ('{"Version":"2012-10-17","Statement":[{'
                  '"Sid":"ElevateReaderOnA","Effect":"Allow","Principal":"*",'
                  '"Action":["s3:PutObject"],'
                  f'"Resource":["arn:aws:s3:::{A}/*"],'
                  '"Condition":{"StringEquals":'
                  f'{{"keystone:userid":"{reader_uid}"}}}}}}]}}')
        member.put_bucket_policy(Bucket=A, Policy=policy)
        print(f"setup: A={A} (policy elevates reader), B={B} (no policy)\n")

        print("reads (reader can always read both):")
        check("reader GetObject  A", lambda: reader.get_object(Bucket=A, Key="seed"), "allow")
        check("reader GetObject  B", lambda: reader.get_object(Bucket=B, Key="seed"), "allow")

        print("\nwrites (policy lifts the cap on A only):")
        check("reader PutObject  A (policy Allow)",
              lambda: reader.put_object(Bucket=A, Key="w", Body=b"hi"), "allow")
        check("reader PutObject  B (no policy -> capped)",
              lambda: reader.put_object(Bucket=B, Key="w", Body=b"hi"), "deny")
    finally:
        for bkt in (A, B):
            try:
                member.delete_bucket_policy(Bucket=bkt)
            except ClientError:
                pass
            try:
                for o in member.list_objects_v2(Bucket=bkt).get("Contents", []):
                    member.delete_object(Bucket=bkt, Key=o["Key"])
                member.delete_bucket(Bucket=bkt)
            except ClientError:
                pass
        print(f"\ncleanup: removed {A}, {B}")

    print(f"\n----- {passed} passed, {failed} failed -----")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
