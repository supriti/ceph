# Reader-role quick test

RGW must be fronted by Keystone with:
`rgw keystone accepted project reader roles = objectstore_viewer`

## 1. Point at Keystone (admin)
```bash
export OS_AUTH_URL=http://KEYSTONE:5000/v3
export OS_USERNAME=admin OS_PASSWORD=PW OS_PROJECT_NAME=admin
export OS_USER_DOMAIN_NAME=Default OS_PROJECT_DOMAIN_NAME=Default OS_IDENTITY_API_VERSION=3
openstack token issue          # sanity: prints a token
```

## 2. Make a reader + a normal member in one project
```bash
openstack role create objectstore_viewer                       # skip if it exists
openstack project create --domain Default proj1
openstack user create --domain Default --password Rpw reader1
openstack user create --domain Default --password Mpw member1
openstack role add --project proj1 --user reader1 objectstore_viewer
openstack role add --project proj1 --user member1 member
```

## 3. Seed a bucket + object as the member (full control)
```bash
export OS_USERNAME=member1 OS_PASSWORD=Mpw OS_PROJECT_NAME=proj1
swift post testcont
echo hello > f.txt && swift upload testcont f.txt
```

## 4. Test as the reader
```bash
export OS_USERNAME=reader1 OS_PASSWORD=Rpw OS_PROJECT_NAME=proj1
swift list testcont              # OK   (read)
swift download testcont f.txt    # OK   (read)
swift upload testcont f.txt      # 403  Forbidden (write denied)
swift delete testcont f.txt      # 403  Forbidden (write denied)
```
**Pass = reads work, writes return 403.**

## S3 instead of Swift (optional)
```bash
# as reader1:
openstack ec2 credentials create           # prints access + secret
aws --endpoint http://RGW:8000 s3 ls s3://testcont           # OK
aws --endpoint http://RGW:8000 s3 cp f.txt s3://testcont/x   # AccessDenied (403)
```

## Dev-container fallback (openstack/swift CLI catalog is broken here → use curl)
```bash
KS=http://host.docker.internal:5000; SW=http://localhost:8000/swift/v1
TOK=$(curl -s -D- -o/dev/null $KS/v3/auth/tokens -H 'Content-Type: application/json' \
  -d '{"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"reader1",
      "domain":{"name":"Default"},"password":"Rpw"}}},"scope":{"project":{"name":"proj1",
      "domain":{"name":"Default"}}}}}' | grep -i '^x-subject-token' | awk '{print $2}' | tr -d '\r')
curl -s -o/dev/null -w "get %{http_code}\n"            -H "X-Auth-Token: $TOK" $SW/testcont/f.txt   # 200
curl -s -o/dev/null -w "put %{http_code}\n" -X PUT -d x -H "X-Auth-Token: $TOK" $SW/testcont/x       # 403
```
