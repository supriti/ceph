// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#include "gtest/gtest.h"
#include <gmock/gmock.h>

#include <arpa/inet.h>
#include <cstring>
#include <string>
#include <vector>

#include "rgw/rgw_kmip_wrapped_dek.h"
#include "rgw/rgw_kmip_sse_s3_backend.h"
#include "common/ceph_context.h"
#include "rgw_common.h"

using testing::_;
using testing::Invoke;

namespace {

void append_u32_be(std::vector<char>& v, uint32_t hostval)
{
  uint32_t be = htonl(hostval);
  const char *p = reinterpret_cast<const char*>(&be);
  v.insert(v.end(), p, p + 4);
}

} // namespace

TEST(RgwKmipWrappedDek, RejectsNullOutOrRaw)
{
  char buf[64]{};
  rgw_kmip_wrapped_dek_parsed p{};
  EXPECT_EQ(rgw_kmip_parse_wrapped_dek(buf, sizeof(buf), nullptr), -EINVAL);
  EXPECT_EQ(rgw_kmip_parse_wrapped_dek(nullptr, 0, &p), -EINVAL);
}

TEST(RgwKmipWrappedDek, RejectsTooShort)
{
  std::vector<char> buf(40, 0);
  rgw_kmip_wrapped_dek_parsed p{};
  EXPECT_EQ(rgw_kmip_parse_wrapped_dek(buf.data(), buf.size(), &p), -EINVAL);
}

TEST(RgwKmipWrappedDek, RejectsWrongTagLength)
{
  std::vector<char> buf;
  append_u32_be(buf, 12); // iv
  append_u32_be(buf, 15); // tag must be 16
  buf.resize(52, 0);
  rgw_kmip_wrapped_dek_parsed p{};
  EXPECT_EQ(rgw_kmip_parse_wrapped_dek(buf.data(), buf.size(), &p), -EINVAL);
}

TEST(RgwKmipWrappedDek, RejectsIvOverflow)
{
  std::vector<char> buf;
  append_u32_be(buf, 1000);
  append_u32_be(buf, 16);
  buf.resize(60, 0);
  rgw_kmip_wrapped_dek_parsed p{};
  EXPECT_EQ(rgw_kmip_parse_wrapped_dek(buf.data(), buf.size(), &p), -EINVAL);
}

TEST(RgwKmipWrappedDek, AcceptsMinimalValidLayout)
{
  std::vector<char> buf;
  append_u32_be(buf, 12);
  append_u32_be(buf, 16);
  buf.resize(8 + 12 + 16 + 16, 0xab);
  rgw_kmip_wrapped_dek_parsed p{};
  ASSERT_EQ(rgw_kmip_parse_wrapped_dek(buf.data(), buf.size(), &p), 0);
  EXPECT_EQ(p.iv_size, 12u);
  EXPECT_EQ(p.tag_size, 16u);
  EXPECT_EQ(p.ciphertext_size, 16);
  EXPECT_EQ(p.iv_ptr, buf.data() + 8);
  EXPECT_EQ(p.tag_ptr, p.iv_ptr + 12);
  EXPECT_EQ(p.ciphertext_ptr, p.tag_ptr + 16);
}

class MockKmipSseS3Backend : public RGWKmipSseS3Backend {
public:
  MOCK_METHOD(int, create_bucket_key,
              (const DoutPrefixProvider * dpp, const std::string &bucket_name,
               std::string &kek_id_out, optional_yield y),
              (override));
  MOCK_METHOD(int, destroy_bucket_key,
              (const DoutPrefixProvider * dpp, const std::string &kek_id,
               optional_yield y),
              (override));
  MOCK_METHOD(int, generate_and_wrap_dek,
              (const DoutPrefixProvider * dpp, const std::string &kek_id,
               const std::string &encryption_context, bufferlist &plaintext_dek_out,
               bufferlist &wrapped_dek_out, optional_yield y),
              (override));
  MOCK_METHOD(int, unwrap_dek,
              (const DoutPrefixProvider * dpp, const std::string &kek_id,
               const bufferlist &wrapped_dek, const std::string &encryption_context,
               bufferlist &plaintext_dek_out, optional_yield y),
              (override));
};

TEST(RgwKmipSseS3Backend, MockCreateReturnsValue)
{
  CephContext *cct = (new CephContext(CEPH_ENTITY_TYPE_ANY))->get();
  const NoDoutPrefix no_dpp(cct, 1);
  MockKmipSseS3Backend mock;
  std::string out;
  EXPECT_CALL(mock, create_bucket_key(_, std::string("bucket"), _, _))
      .WillOnce(Invoke([](const DoutPrefixProvider *, const std::string &,
                          std::string &id, optional_yield) {
        id = "test-kek-id";
        return 0;
      }));
  int r = mock.create_bucket_key(&no_dpp, "bucket", out, null_yield);
  ASSERT_EQ(r, 0);
  EXPECT_EQ(out, "test-kek-id");
  cct->put();
}
