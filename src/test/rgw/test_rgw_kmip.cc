// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#include "gtest/gtest.h"
#include <gmock/gmock.h>

#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "rgw/rgw_kmip_wrapped_dek.h"
#include "rgw/rgw_kmip_sse_s3_backend.h"
#include "include/buffer.h"
#include "common/ceph_context.h"
#include "rgw_common.h"

using testing::_;
using testing::Invoke;
using testing::Return;

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

TEST(RgwKmipWrappedDek, RejectsZeroCiphertext)
{
  /* iv=12, tag=16, payload length 0 — parser requires ct_size > 0 */
  std::vector<char> buf;
  append_u32_be(buf, 12);
  append_u32_be(buf, 16);
  buf.resize(8 + 12 + 16, 0);
  rgw_kmip_wrapped_dek_parsed p{};
  EXPECT_EQ(rgw_kmip_parse_wrapped_dek(buf.data(), buf.size(), &p), -EINVAL);
}

TEST(RgwKmipWrappedDek, RejectsTruncatedBeforeIvTagPayload)
{
  /* iv=12 tag=16 => need 8+12+16=36 bytes; 35 bytes total => need > len */
  std::vector<char> buf;
  append_u32_be(buf, 12);
  append_u32_be(buf, 16);
  buf.resize(35, 0);
  rgw_kmip_wrapped_dek_parsed p{};
  EXPECT_EQ(rgw_kmip_parse_wrapped_dek(buf.data(), buf.size(), &p), -EINVAL);
}

TEST(RgwKmipWrappedDek, RejectsLengthBelowMinimum)
{
  std::vector<char> buf(51, 0);
  rgw_kmip_wrapped_dek_parsed p{};
  EXPECT_EQ(rgw_kmip_parse_wrapped_dek(buf.data(), buf.size(), &p), -EINVAL);
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

TEST(RgwKmipSseS3Backend, MockDestroySucceeds)
{
  CephContext *cct = (new CephContext(CEPH_ENTITY_TYPE_ANY))->get();
  const NoDoutPrefix no_dpp(cct, 1);
  MockKmipSseS3Backend mock;
  EXPECT_CALL(mock, destroy_bucket_key(_, std::string("kek-uuid"), _))
      .WillOnce(Return(0));
  int r = mock.destroy_bucket_key(&no_dpp, "kek-uuid", null_yield);
  ASSERT_EQ(r, 0);
  cct->put();
}

TEST(RgwKmipSseS3Backend, MockWrapPopulatesOutputs)
{
  CephContext *cct = (new CephContext(CEPH_ENTITY_TYPE_ANY))->get();
  const NoDoutPrefix no_dpp(cct, 1);
  MockKmipSseS3Backend mock;
  bufferlist plain;
  bufferlist wrapped;
  EXPECT_CALL(mock, generate_and_wrap_dek(_, std::string("kek"), std::string("ctx"), _, _, _))
      .WillOnce(Invoke([](const DoutPrefixProvider *, const std::string &,
                          const std::string &, bufferlist &plain_out,
                          bufferlist &wrapped_out, optional_yield) {
        plain_out.append("01234567890123456789012345678901", 32);
        wrapped_out.append("hdr-and-payload", 15);
        return 0;
      }));
  int r = mock.generate_and_wrap_dek(&no_dpp, "kek", "ctx", plain, wrapped, null_yield);
  ASSERT_EQ(r, 0);
  ASSERT_EQ(plain.length(), 32u);
  ASSERT_EQ(wrapped.length(), 15u);
  cct->put();
}

TEST(RgwKmipSseS3Backend, MockUnwrapReturnsPlaintext)
{
  CephContext *cct = (new CephContext(CEPH_ENTITY_TYPE_ANY))->get();
  const NoDoutPrefix no_dpp(cct, 1);
  MockKmipSseS3Backend mock;
  bufferlist wrapped;
  wrapped.append("opaque-wrapped-blob");

  bufferlist plain_out;
  EXPECT_CALL(mock, unwrap_dek(_, std::string("kek"), _, std::string("ctx"), _, _))
      .WillOnce(Invoke([](const DoutPrefixProvider *, const std::string &,
                          const bufferlist &, const std::string &,
                          bufferlist &out, optional_yield) {
        out.append("01234567890123456789012345678901", 32);
        return 0;
      }));
  int r = mock.unwrap_dek(&no_dpp, "kek", wrapped, "ctx", plain_out, null_yield);
  ASSERT_EQ(r, 0);
  ASSERT_EQ(plain_out.length(), 32u);
  cct->put();
}

// ============ Additional wrapped DEK parser tests ============

TEST(RgwKmipWrappedDek, AcceptsLargerIv)
{
  /* iv=16, tag=16, ciphertext=32 => total = 8+16+16+32 = 72 */
  std::vector<char> buf;
  append_u32_be(buf, 16);
  append_u32_be(buf, 16);
  buf.resize(8 + 16 + 16 + 32, 0xcc);
  rgw_kmip_wrapped_dek_parsed p{};
  ASSERT_EQ(rgw_kmip_parse_wrapped_dek(buf.data(), buf.size(), &p), 0);
  EXPECT_EQ(p.iv_size, 16u);
  EXPECT_EQ(p.tag_size, 16u);
  EXPECT_EQ(p.ciphertext_size, 32u);
}

TEST(RgwKmipWrappedDek, AcceptsTypicalAesGcmBlob)
{
  /* Typical AES-256-GCM: iv=12, tag=16, ciphertext=32 (256-bit DEK) */
  std::vector<char> buf;
  append_u32_be(buf, 12);
  append_u32_be(buf, 16);
  buf.resize(8 + 12 + 16 + 32, 0xdd);
  rgw_kmip_wrapped_dek_parsed p{};
  ASSERT_EQ(rgw_kmip_parse_wrapped_dek(buf.data(), buf.size(), &p), 0);
  EXPECT_EQ(p.iv_size, 12u);
  EXPECT_EQ(p.ciphertext_size, 32u);
  /* Verify pointers are contiguous and ordered */
  EXPECT_EQ(p.iv_ptr, buf.data() + 8);
  EXPECT_EQ(p.tag_ptr, buf.data() + 8 + 12);
  EXPECT_EQ(p.ciphertext_ptr, buf.data() + 8 + 12 + 16);
}

TEST(RgwKmipWrappedDek, ZeroIvAccepted)
{
  /* iv=0, tag=16; with len=52: ct = 52-8-0-16 = 28 */
  std::vector<char> buf;
  append_u32_be(buf, 0);
  append_u32_be(buf, 16);
  buf.resize(52, 0);
  rgw_kmip_wrapped_dek_parsed p{};
  EXPECT_EQ(rgw_kmip_parse_wrapped_dek(buf.data(), buf.size(), &p), 0);
  EXPECT_EQ(p.iv_size, 0u);
  EXPECT_EQ(p.ciphertext_size, 28u);
}

TEST(RgwKmipWrappedDek, RejectsTagNotSixteen)
{
  /* tag must be exactly 16 (AES-GCM tag); try 8 */
  std::vector<char> buf;
  append_u32_be(buf, 12);
  append_u32_be(buf, 8);
  buf.resize(8 + 12 + 8 + 32, 0);
  rgw_kmip_wrapped_dek_parsed p{};
  EXPECT_EQ(rgw_kmip_parse_wrapped_dek(buf.data(), buf.size(), &p), -EINVAL);
}

TEST(RgwKmipWrappedDek, RejectsTagZero)
{
  std::vector<char> buf;
  append_u32_be(buf, 12);
  append_u32_be(buf, 0);
  buf.resize(52, 0);
  rgw_kmip_wrapped_dek_parsed p{};
  EXPECT_EQ(rgw_kmip_parse_wrapped_dek(buf.data(), buf.size(), &p), -EINVAL);
}

TEST(RgwKmipWrappedDek, ExactMinimumSizeIs52)
{
  /* Minimum valid: iv=12, tag=16, ct=16 => 8+12+16+16=52 */
  std::vector<char> buf;
  append_u32_be(buf, 12);
  append_u32_be(buf, 16);
  buf.resize(52, 0xaa);
  rgw_kmip_wrapped_dek_parsed p{};
  ASSERT_EQ(rgw_kmip_parse_wrapped_dek(buf.data(), buf.size(), &p), 0);
  EXPECT_EQ(p.ciphertext_size, 16u);

  /* 51 bytes should fail */
  buf.resize(51);
  EXPECT_EQ(rgw_kmip_parse_wrapped_dek(buf.data(), buf.size(), &p), -EINVAL);
}

TEST(RgwKmipWrappedDek, LargeCiphertextAccepted)
{
  /* iv=12, tag=16, ciphertext=4096 */
  std::vector<char> buf;
  append_u32_be(buf, 12);
  append_u32_be(buf, 16);
  buf.resize(8 + 12 + 16 + 4096, 0xff);
  rgw_kmip_wrapped_dek_parsed p{};
  ASSERT_EQ(rgw_kmip_parse_wrapped_dek(buf.data(), buf.size(), &p), 0);
  EXPECT_EQ(p.ciphertext_size, 4096u);
}

// ============ Additional mock backend tests ============

TEST(RgwKmipSseS3Backend, CreateFailurePropagates)
{
  CephContext *cct = (new CephContext(CEPH_ENTITY_TYPE_ANY))->get();
  const NoDoutPrefix no_dpp(cct, 1);
  MockKmipSseS3Backend mock;
  std::string out;
  EXPECT_CALL(mock, create_bucket_key(_, std::string("bucket"), _, _))
      .WillOnce(Return(-EIO));
  int r = mock.create_bucket_key(&no_dpp, "bucket", out, null_yield);
  EXPECT_EQ(r, -EIO);
  EXPECT_TRUE(out.empty());
  cct->put();
}

TEST(RgwKmipSseS3Backend, DestroyFailurePropagates)
{
  CephContext *cct = (new CephContext(CEPH_ENTITY_TYPE_ANY))->get();
  const NoDoutPrefix no_dpp(cct, 1);
  MockKmipSseS3Backend mock;
  EXPECT_CALL(mock, destroy_bucket_key(_, std::string("kek-uuid"), _))
      .WillOnce(Return(-ENOENT));
  int r = mock.destroy_bucket_key(&no_dpp, "kek-uuid", null_yield);
  EXPECT_EQ(r, -ENOENT);
  cct->put();
}

TEST(RgwKmipSseS3Backend, WrapFailureLeavesOutputsEmpty)
{
  CephContext *cct = (new CephContext(CEPH_ENTITY_TYPE_ANY))->get();
  const NoDoutPrefix no_dpp(cct, 1);
  MockKmipSseS3Backend mock;
  bufferlist plain;
  bufferlist wrapped;
  EXPECT_CALL(mock, generate_and_wrap_dek(_, _, _, _, _, _))
      .WillOnce(Return(-EIO));
  int r = mock.generate_and_wrap_dek(&no_dpp, "kek", "ctx", plain, wrapped, null_yield);
  EXPECT_EQ(r, -EIO);
  EXPECT_EQ(plain.length(), 0u);
  EXPECT_EQ(wrapped.length(), 0u);
  cct->put();
}

TEST(RgwKmipSseS3Backend, UnwrapFailureLeavesOutputEmpty)
{
  CephContext *cct = (new CephContext(CEPH_ENTITY_TYPE_ANY))->get();
  const NoDoutPrefix no_dpp(cct, 1);
  MockKmipSseS3Backend mock;
  bufferlist wrapped;
  wrapped.append("opaque-wrapped-blob");
  bufferlist plain_out;
  EXPECT_CALL(mock, unwrap_dek(_, _, _, _, _, _))
      .WillOnce(Return(-EKEYREJECTED));
  int r = mock.unwrap_dek(&no_dpp, "kek", wrapped, "ctx", plain_out, null_yield);
  EXPECT_EQ(r, -EKEYREJECTED);
  EXPECT_EQ(plain_out.length(), 0u);
  cct->put();
}

TEST(RgwKmipSseS3Backend, WrapUnwrapRoundTrip)
{
  /* Simulate a full wrap -> unwrap cycle through mocks.
   * The mock "wraps" by prepending a tag and "unwraps" by stripping it. */
  CephContext *cct = (new CephContext(CEPH_ENTITY_TYPE_ANY))->get();
  const NoDoutPrefix no_dpp(cct, 1);
  MockKmipSseS3Backend mock;

  const std::string kek = "test-kek-id";
  const std::string ctx = "arn:aws:s3:::bucket/object";
  const char dek_bytes[32] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20
  };

  /* Mock wrapping: return known DEK as plaintext + "WRAPPED:" prefix as wrapped */
  EXPECT_CALL(mock, generate_and_wrap_dek(_, kek, ctx, _, _, _))
      .WillOnce(Invoke([&](const DoutPrefixProvider *, const std::string &,
                           const std::string &, bufferlist &plain_out,
                           bufferlist &wrapped_out, optional_yield) {
        plain_out.append(dek_bytes, 32);
        wrapped_out.append("WRAPPED:");
        wrapped_out.append(dek_bytes, 32);
        return 0;
      }));

  bufferlist plain_dek, wrapped_dek;
  ASSERT_EQ(mock.generate_and_wrap_dek(&no_dpp, kek, ctx,
            plain_dek, wrapped_dek, null_yield), 0);
  ASSERT_EQ(plain_dek.length(), 32u);
  ASSERT_GT(wrapped_dek.length(), 32u);

  /* Mock unwrapping: strip "WRAPPED:" prefix and return the DEK */
  EXPECT_CALL(mock, unwrap_dek(_, kek, _, ctx, _, _))
      .WillOnce(Invoke([](const DoutPrefixProvider *, const std::string &,
                          const bufferlist &wrapped_in, const std::string &,
                          bufferlist &plain_out, optional_yield) {
        std::string w = wrapped_in.to_str();
        if (w.substr(0, 8) != "WRAPPED:") return -EINVAL;
        plain_out.append(w.data() + 8, w.size() - 8);
        return 0;
      }));

  bufferlist unwrapped;
  ASSERT_EQ(mock.unwrap_dek(&no_dpp, kek, wrapped_dek, ctx,
            unwrapped, null_yield), 0);
  ASSERT_EQ(unwrapped.length(), 32u);

  /* The unwrapped DEK must match the original plaintext DEK */
  EXPECT_TRUE(plain_dek.contents_equal(unwrapped));
  cct->put();
}

TEST(RgwKmipSseS3Backend, DifferentContextProducesDifferentWrapped)
{
  CephContext *cct = (new CephContext(CEPH_ENTITY_TYPE_ANY))->get();
  const NoDoutPrefix no_dpp(cct, 1);
  MockKmipSseS3Backend mock;

  int call_count = 0;
  EXPECT_CALL(mock, generate_and_wrap_dek(_, _, _, _, _, _))
      .Times(2)
      .WillRepeatedly(Invoke([&](const DoutPrefixProvider *,
                                 const std::string &,
                                 const std::string &ctx,
                                 bufferlist &plain_out,
                                 bufferlist &wrapped_out, optional_yield) {
        plain_out.append("01234567890123456789012345678901", 32);
        wrapped_out.append(ctx);
        wrapped_out.append(":ciphertext");
        call_count++;
        return 0;
      }));

  bufferlist p1, w1, p2, w2;
  ASSERT_EQ(mock.generate_and_wrap_dek(&no_dpp, "kek", "ctx-A",
            p1, w1, null_yield), 0);
  ASSERT_EQ(mock.generate_and_wrap_dek(&no_dpp, "kek", "ctx-B",
            p2, w2, null_yield), 0);
  EXPECT_EQ(call_count, 2);
  EXPECT_EQ(p1.length(), p2.length());
  /* Different context must produce different wrapped blobs */
  EXPECT_FALSE(w1.contents_equal(w2));
  cct->put();
}
