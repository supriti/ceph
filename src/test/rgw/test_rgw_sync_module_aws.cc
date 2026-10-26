// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 smarttab ft=cpp

/*
 * Destination path construction for the cloud sync module.
 *
 * The property these tests exist to protect is that two distinct source
 * buckets never produce the same destination path. Tenant names cannot
 * contain '-' but bucket names can, so joining them with '-' made
 * tenant "proj1" + bucket "data" collide with the untenanted bucket
 * "proj1-data", and the second one to replicate silently overwrote the first.
 */

#include <gtest/gtest.h>

#include "common/ceph_context.h"
#include "rgw_common.h"

#include "driver/rados/rgw_sync_module_aws.cc"

namespace {

/* get_path() logs on the rejection path, so it needs a real context. */
auto cct = std::make_unique<CephContext>(CEPH_ENTITY_TYPE_ANY);
NoDoutPrefix dp(cct.get(), ceph_subsys_rgw);

std::shared_ptr<AWSSyncConfig_Profile> profile(const string& target_path)
{
  auto p = std::make_shared<AWSSyncConfig_Profile>();
  p->target_path = target_path;
  return p;
}

RGWBucketInfo bucket(const string& tenant, const string& name)
{
  RGWBucketInfo info;
  info.bucket.tenant = tenant;
  info.bucket.name = name;
  return info;
}

/* get_path() for a bucket, or the error it returned. */
int path_of(const string& target_path, const RGWBucketInfo& info,
            const string& key, string *out)
{
  AWSSyncConfig conf;
  auto p = profile(target_path);
  return conf.get_path(&dp, p, info, rgw_obj_key(key), out);
}

} // namespace

/*
 * The regression. Before the fix both of these produced
 * "<target>/proj1-data/secret.txt" and the destination kept only one object.
 */
TEST(AWSSyncPath, TenantedAndUntenantedDoNotCollide)
{
  const string target = "dest/${bucket}";

  string tenanted, untenanted;
  ASSERT_EQ(0, path_of(target, bucket("proj1", "data"), "secret.txt", &tenanted));
  ASSERT_EQ(0, path_of(target, bucket("", "proj1-data"), "secret.txt", &untenanted));

  EXPECT_NE(tenanted, untenanted);
  EXPECT_EQ("dest/proj1/data/secret.txt", tenanted);
  EXPECT_EQ("dest/proj1-data/secret.txt", untenanted);
}

TEST(AWSSyncPath, UntenantedBucketIsUnchanged)
{
  string path;
  ASSERT_EQ(0, path_of("dest/${bucket}", bucket("", "data"), "obj", &path));
  EXPECT_EQ("dest/data/obj", path);
}

/* The shipped default puts ${bucket} in the key, so tenanted buckets work. */
TEST(AWSSyncPath, DefaultTargetPathAcceptsTenantedBucket)
{
  string path;
  ASSERT_EQ(0, path_of(default_target_path, bucket("proj1", "data"), "obj", &path));
  EXPECT_EQ("rgw-${zonegroup}-${sid}/proj1/data/obj", path);
}

/*
 * A target_path with no '/' ahead of ${bucket} expands it into the
 * destination *bucket name*, which cannot hold the '/' qualifier. Rather
 * than emit a name the destination will reject - or silently drop the
 * tenant - refuse the sync and say why.
 */
TEST(AWSSyncPath, TenantedBucketRejectedWhenBucketIsTheDestinationBucketName)
{
  string path;
  EXPECT_EQ(-EINVAL,
            path_of("${bucket}", bucket("proj1", "data"), "obj", &path));
  EXPECT_EQ(-EINVAL,
            path_of("${bucket}/sub", bucket("proj1", "data"), "obj", &path));
}

/* Untenanted buckets are unaffected by that restriction. */
TEST(AWSSyncPath, UntenantedBucketAllowedAsDestinationBucketName)
{
  string path;
  ASSERT_EQ(0, path_of("${bucket}", bucket("", "data"), "obj", &path));
  EXPECT_EQ("data/obj", path);
}

/* ${owner} keeps its historical "<tenant>-<owner>" form; it is a separate
 * substitution and plays no part in the collision. */
TEST(AWSSyncPath, OwnerKeepsHyphenForm)
{
  RGWBucketInfo info = bucket("proj1", "data");
  info.owner = parse_owner("alice");

  string path;
  ASSERT_EQ(0, path_of("dest/${owner}/${bucket}", info, "obj", &path));
  EXPECT_EQ("dest/proj1-alice/proj1/data/obj", path);
}

/*
 * get_target() splits the path into destination bucket and key at the first
 * '/'. With a tenanted bucket the tenant qualifier must land in the key, not
 * in the bucket name.
 */
TEST(AWSSyncPath, GetTargetSplitsBucketAndKey)
{
  AWSSyncConfig conf;
  auto p = profile("dest/${bucket}");

  string bucket_name, obj_name;
  ASSERT_EQ(0, conf.get_target(&dp, p, bucket("proj1", "data"),
                               rgw_obj_key("secret.txt"),
                               &bucket_name, &obj_name));
  EXPECT_EQ("dest", bucket_name);
  EXPECT_EQ("proj1/data/secret.txt", obj_name);
}

/* Versioned objects carry the instance id into the key, unchanged by the fix. */
TEST(AWSSyncPath, VersionInstanceAppendedToKey)
{
  AWSSyncConfig conf;
  auto p = profile("dest/${bucket}");

  rgw_obj_key key("secret.txt");
  key.instance = "v2";

  string path;
  ASSERT_EQ(0, conf.get_path(&dp, p, bucket("proj1", "data"), key, &path));
  EXPECT_EQ("dest/proj1/data/secret.txt:v2", path);
}
