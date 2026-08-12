#!/usr/bin/env python3
"""Build a coverage matrix of every RGWOp: declared op_mask x how it authorizes.

Purpose: find ops that mutate state but whose verify_permission() never routes
through a helper that consults s->perm_mask / IAM, i.e. the leak candidates for
a capped (project-reader / implicit-deny) Keystone identity.
"""
import re, os, sys, glob, collections

ROOT = sys.argv[1] if len(sys.argv) > 1 else "/workspaces/ceph/src/rgw"
FILES = []
for pat in ("*.h", "*.cc", "driver/rados/*.h", "driver/rados/*.cc"):
    FILES += glob.glob(os.path.join(ROOT, pat))

src = {}
for f in FILES:
    try:
        src[f] = open(f, encoding="utf-8", errors="replace").read()
    except OSError:
        pass

# ---- 1. inheritance graph -------------------------------------------------
bases = {}
CLASS_RE = re.compile(
    r'\bclass\s+([A-Za-z_]\w*)\s*(?::\s*([^{;]+))?\{', re.S)
for f, text in src.items():
    for m in CLASS_RE.finditer(text):
        name, inherit = m.group(1), m.group(2) or ""
        parents = re.findall(r'(?:public|protected|private|virtual)\s+([A-Za-z_][\w:<>, ]*)',
                             inherit)
        parents = [p.strip().split('<')[0].split('::')[-1].strip() for p in parents]
        bases.setdefault(name, [])
        for p in parents:
            if p and p not in bases[name]:
                bases[name].append(p)

def mro(cls, seen=None):
    seen = seen or []
    if cls in seen:
        return seen
    seen = seen + [cls]
    for p in bases.get(cls, []):
        seen = mro(p, seen)
    return seen

# ---- 2. helper: extract a brace-balanced body starting at index i ---------
def body_at(text, i):
    d, start = 0, text.find('{', i)
    if start < 0:
        return ""
    for j in range(start, min(len(text), start + 200000)):
        c = text[j]
        if c == '{':
            d += 1
        elif c == '}':
            d -= 1
            if d == 0:
                return text[start:j + 1]
    return text[start:start + 4000]

# ---- 3. per-class members: get_type, op_mask, verify_permission ----------
optype = {}     # class -> RGW_OP_*
opmask = {}     # class -> mask expression
verify = {}     # class -> verify_permission body
for f, text in src.items():
    for m in re.finditer(r'\bRGWOpType\s+(?:(\w+)::)?get_type\(\)[^{;]*\{([^}]*)\}', text):
        cls, bod = m.group(1), m.group(2)
        t = re.search(r'(RGW_OP_\w+)', bod)
        if not t:
            continue
        if cls:
            optype[cls] = t.group(1)
        else:
            # in-class definition: nearest preceding "class X"
            pre = text[:m.start()]
            c = None
            for cm in CLASS_RE.finditer(pre):
                c = cm.group(1)
            if c:
                optype[c] = t.group(1)

    for m in re.finditer(r'\buint32_t\s+(?:(\w+)::)?op_mask\(\)', text):
        cls = m.group(1)
        if not cls:
            pre = text[:m.start()]
            c = None
            for cm in CLASS_RE.finditer(pre):
                c = cm.group(1)
            cls = c
        if not cls:
            continue
        b = body_at(text, m.end())
        masks = re.findall(r'RGW_OP_TYPE_\w+', b)
        opmask[cls] = "|".join(sorted(set(masks))) if masks else ("0" if "return 0" in b else "?")

    for m in re.finditer(r'\bint\s+(?:(\w+)::)?verify_permission\s*\(', text):
        cls = m.group(1)
        if not cls:
            pre = text[:m.start()]
            c = None
            for cm in CLASS_RE.finditer(pre):
                c = cm.group(1)
            cls = c
        if not cls:
            continue
        seg = text[m.start():m.start() + 300]
        if ';' in seg.split('{')[0]:      # pure declaration
            continue
        verify[cls] = body_at(text, m.end())

# ---- 4. classify the authorization mechanism ----------------------------
HELPERS = [
    ("bucket-acl/iam", r'verify_bucket_permission'),
    ("object-acl/iam", r'verify_object_permission'),
    ("user-acl/iam",   r'verify_user_permission'),
    ("topic-policy",   r'verify_topic_permission|topic_has_policy|verify_topic'),
    ("iam-eval",       r'evaluate_iam_policies|eval_identity_or_session_policies|->eval\('),
    ("perm_mask-cap",  r'is_capped_keystone_identity'),
    ("owner-only",     r'is_owner\b|get_owner\(\)\s*==|is_owner_of'),
    ("admin-only",     r'is_admin_of|->is_admin\b|system_request'),
]

def classify(cls):
    """Walk the MRO until a class supplies verify_permission."""
    for c in mro(cls):
        if c in verify:
            b = verify[c]
            tags = [n for n, rx in HELPERS if re.search(rx, b)]
            if not tags:
                if re.search(r'return\s+0\s*;', b) and len(b) < 400:
                    tags = ["NO-CHECK(return 0)"]
                else:
                    tags = ["UNCLASSIFIED"]
            return c, tags
    return None, ["INHERITED-DEFAULT(RGWOp::verify_permission)"]

def eff_mask(cls):
    for c in mro(cls):
        if c in opmask:
            return opmask[c]
    return "(none => 0)"

rows = []
for cls, t in sorted(optype.items()):
    where, tags = classify(cls)
    rows.append((cls, t, eff_mask(cls), where or "-", ",".join(tags)))

MUT = lambda m: ("WRITE" in m or "DELETE" in m or "MODIFY" in m)
SAFE = ("bucket-acl/iam", "object-acl/iam", "user-acl/iam", "perm_mask-cap")

print(f"# ops with a get_type(): {len(rows)}   (enum has "
      f"{len(re.findall(r'^  RGW_OP', open(os.path.join(ROOT,'rgw_op_type.h')).read(), re.M))} entries)\n")

print("=" * 108)
print("MUTATING OPS WHOSE AUTH PATH NEVER TOUCHES perm_mask / ACL / IAM  <-- leak candidates")
print("=" * 108)
print(f"{'class':<44}{'op_mask':<26}{'verify_permission in':<30}mechanism")
holes = []
for cls, t, m, where, tags in rows:
    if MUT(m) and not any(s in tags for s in SAFE):
        holes.append((cls, t, m, where, tags))
        print(f"{cls:<44}{m:<26}{where:<30}{tags}")
print(f"\n-> {len(holes)} leak candidates\n")

print("=" * 108)
print("OPS DECLARING NO MUTATION MASK (READ or none) — mis-declaration would bypass any op_mask gate")
print("=" * 108)
for cls, t, m, where, tags in rows:
    if not MUT(m):
        print(f"{cls:<44}{m:<26}{where:<30}{tags}")

print("\n" + "=" * 108)
print("HISTOGRAM of mechanisms")
print("=" * 108)
h = collections.Counter()
for cls, t, m, where, tags in rows:
    h[tags] += 1
for k, v in h.most_common():
    print(f"{v:>4}  {k}")
