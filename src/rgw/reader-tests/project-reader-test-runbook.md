# Project-reader / implicit-deny — test runbook

How to verify the Keystone project-reader cap (and the role-collapse refactor)
on your own. Three layers, fastest first:

| Layer | Needs a cluster? | Proves |
|-------|------------------|--------|
| 1. Unit tests (`unittest_rgw_keystone`) | No | roles → permission mask/tier + the enforcement gate, in isolation |
| 2. S3 + SNS matrix (`test_reader_api_matrix.py`) | Yes (RGW + Keystone) | reader is read-only on the live S3 + SNS client surface |
| 3. Swift curl sweep (below) | Yes (RGW + Keystone) | same cap holds over the Swift protocol (second frontend) |

Layer 1 is the authoritative "which mask does a role combo get" test and runs in
seconds with no cluster. Layers 2–3 are live differential checks (reader vs a
full-control member) over the two real client protocols.

---

## 0. Prerequisites

**Dev container config** (already set in `build/ceph.conf`):

```
rgw keystone url = http://host.docker.internal:5000
rgw keystone accepted roles = admin, member, objectstore_viewer
rgw keystone accepted project reader roles = objectstore_viewer
rgw keystone implicit tenants = true
rgw s3 auth use keystone = true
```

- **Reader role** = `objectstore_viewer` → mask `READ | READ_ACP` (0x05).
- **Member role** = `member` → full control (the control/baseline user).
- **implicit-deny** is exercised by the **unit tests only** (not wired into
  `ceph.conf` live); it maps a role to mask 0.

**Python deps** for layer 2:

```bash
python3 -c "import requests, boto3" || pip install requests boto3
```

**Both services must be up** before layers 2–3:

```bash
curl -s -o /dev/null -w "keystone %{http_code}\n" http://host.docker.internal:5000/v3   # want 200/300
curl -s -o /dev/null -w "rgw %{http_code}\n"      http://localhost:8000/                # want 200
```

---

## 1. Unit tests (no cluster needed)

```bash
ninja -C build unittest_rgw_keystone
./build/bin/unittest_rgw_keystone
```

Expected tail:

```
[==========] 23 tests from 4 test suites ran.
[  PASSED  ] 23 tests.
```

What the 23 tests cover (in `src/test/rgw/test_rgw_keystone.cc`):

- **`KeystoneProjectReader` / `KeystoneImplicitDeny`** — `update_roles()` →
  `effective_perm_mask()` / `admitted()`: reader-only → `READ|READ_ACP`;
  member/admin → `FULL_CONTROL`; implicit-deny only → admitted but mask 0;
  no accepted role → *not* admitted; most-permissive role wins.
- **`KeystoneCapEnforcement`** — the mask actually blocks writes at the
  `verify_*_permission` gate (ACL grants can't exceed the mask; account-scoped
  writes stay blocked for a capped identity).
- **`KeystoneOwnerCap`** — the owner-grant path (`verify_owner_permission`):
  a reader who *is* the project owner still can't write (bucket mdsearch, SNS
  topics); SNS op → permission classification.

To run one suite: `./build/bin/unittest_rgw_keystone --gtest_filter='KeystoneOwnerCap.*'`

---

## 2. S3 + SNS matrix (live)

Self-contained: it provisions its own Keystone fixtures (project
`rgw-reader-matrix`, users `matrix-reader` / `matrix-member`) via raw REST and
mints EC2 keys, then drives ~48 checks.

```bash
python3 src/rgw/reader-tests/test_reader_api_matrix.py
```

Expected tail:

```
----- 48 passed, 0 failed, 1 unexpected-code -----
```

Rules it enforces (see the docstring at the top of the file):

- **READ / READ_ACP op** passes if it does **not** return 403 (a 200, or a
  benign 404 like `NoSuchBucketPolicy`, both mean "permission granted").
- **WRITE / WRITE_ACP op** passes only on **403**. A 2xx = the cap leaked.
- The single `unexpected-code` line (`DeleteBucketWebsite` → 405) is a
  no-mutation non-issue, counted as a pass.

Covers the S3 surface in `rgw_op.cc` (get/put/delete object, all the bucket
sub-resource get/put/delete pairs, listing, multipart, object-lock, ...) grouped
by permission class, plus the SNS topic ops in `rgw_rest_pubsub.cc`
(create/get/set/delete/list).

---

## 3. Swift curl sweep (live, second protocol)

Same cap, exercised through the Swift frontend with token auth (no EC2 keys,
no signature). Reuses the users the matrix already provisioned. Paste this whole
block:

```bash
KS=http://host.docker.internal:5000; SW=http://localhost:8000/swift/v1
tok() {  # tok <user> <pass> <project>  -> scoped Keystone token
  curl -s -D - -o /dev/null $KS/v3/auth/tokens -H 'Content-Type: application/json' \
    -d '{"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"'"$1"'","domain":{"name":"Default"},"password":"'"$2"'"}}},"scope":{"project":{"name":"'"$3"'","domain":{"name":"Default"}}}}}' \
    | grep -i '^x-subject-token' | awk '{print $2}' | tr -d '\r'
}
READER=$(tok matrix-reader readerpass rgw-reader-matrix)
MEMBER=$(tok matrix-member memberpass rgw-reader-matrix)
echo "tokens: reader=${#READER} member=${#MEMBER}"   # both should be 183, non-zero
[ -z "$READER" -o -z "$MEMBER" ] && { echo "TOKEN FETCH FAILED (keystone flaky? see gotchas)"; return; }

echo "== member seed (expect 2xx) =="
curl -s -o /dev/null -w "create container : %{http_code}\n" -X PUT    -H "X-Auth-Token: $MEMBER" $SW/scw
curl -s -o /dev/null -w "put object       : %{http_code}\n" -X PUT    -H "X-Auth-Token: $MEMBER" -d hello $SW/scw/o1
echo "== reader reads (expect 2xx) =="
curl -s -o /dev/null -w "list account     : %{http_code}\n"           -H "X-Auth-Token: $READER" $SW
curl -s -o /dev/null -w "get object       : %{http_code}\n"           -H "X-Auth-Token: $READER" $SW/scw/o1
echo "== reader writes (expect 403) =="
curl -s -o /dev/null -w "put object       : %{http_code}\n" -X PUT    -H "X-Auth-Token: $READER" -d x $SW/scw/o2
curl -s -o /dev/null -w "delete object    : %{http_code}\n" -X DELETE -H "X-Auth-Token: $READER" $SW/scw/o1
curl -s -o /dev/null -w "create container : %{http_code}\n" -X PUT    -H "X-Auth-Token: $READER" $SW/newc
echo "== cleanup =="
curl -s -o /dev/null -w "del obj %{http_code}" -X DELETE -H "X-Auth-Token: $MEMBER" $SW/scw/o1
curl -s -o /dev/null -w " / cont %{http_code}\n" -X DELETE -H "X-Auth-Token: $MEMBER" $SW/scw
```

**Pass = member seed all 2xx, reader reads all 2xx, reader writes all 403.**
A reader write that returns 2xx = the cap leaked; a reader read that returns 403
= a read is wrongly blocked.

---

## Appendix — operational gotchas (all hit during this work)

### Bring the cluster up (reuse existing data, no `-n`)
```bash
cd build && env RGW=1 MDS=0 MGR=1 OSD=1 MON=1 ../src/vstart.sh
```

### Restart just RGW after rebuilding `radosgw`
vstart doesn't cleanly restart the gateway, so kill + relaunch:
```bash
ninja -C build radosgw
pkill -9 -f "bin/radosgw.*client.rgw.8000"
export LD_LIBRARY_PATH=$PWD/build/lib:$LD_LIBRARY_PATH
build/bin/radosgw -c build/ceph.conf \
  --log-file=build/out/radosgw.8000.log \
  --admin-socket=build/out/radosgw.8000.asok \
  --pid-file=build/out/radosgw.8000.pid \
  -n client.rgw.8000 --rgw_frontends="beast port=8000" &
curl -s --retry 20 --retry-connrefused --retry-delay 1 -o /dev/null -w "rgw %{http_code}\n" http://localhost:8000/
```

### Version skew (`ceph-mon` refuses `libec_jerasure.so`)
Happens after the commit hash changes (e.g. rebasing/folding commits) or after a
partial targeted rebuild: mon and the plugin end up at different git versions and
the cluster won't start. Fix with a full rebuild so every target is consistent:
```bash
ninja -C build
```
Verify: `build/bin/ceph-mon --version` and the plugin string should match.

### Keystone container is flaky (this cost the most time)
Symptoms, all container-side (not a code bug):
- `GET /v3` returns 200 but **`POST /v3/auth/tokens` hangs / `curl exit 52`** (empty reply).
- After a restart, a token can come back `201` on POST but then **`401` / `500`**
  when used on a follow-up request (Fernet-key inconsistency across workers).

Fix: **restart the Keystone container on the host** (`docker restart <keystone>`).
Then confirm it's *stable* — a token must both issue **and** validate, not just POST:
```bash
KS=http://host.docker.internal:5000
ST=$(curl -s -D - -o /dev/null $KS/v3/auth/tokens -H 'Content-Type: application/json' \
  -d '{"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"admin","domain":{"name":"Default"},"password":"password"}}},"scope":{"project":{"name":"admin","domain":{"name":"Default"}}}}}' \
  | grep -i '^x-subject-token' | awk '{print $2}' | tr -d '\r')
curl -s -o /dev/null -w "validate -> %{http_code}\n" -H "X-Auth-Token: $ST" "$KS/v3/domains?name=Default"   # want 200
```

### `openstack` CLI doesn't work from the dev container
It authenticates, then re-discovers the identity endpoint from Keystone's service
catalog, which advertises the container-internal hostname (`http://<id>:5000`) —
unresolvable from here. Provision with **raw curl/REST** to
`host.docker.internal:5000` instead (what `test_reader_api_matrix.py` and the
Swift block above do).
