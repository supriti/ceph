// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#pragma once

#include <cstddef>
#include <cstdint>

/**
 * Parsed layout of RGW-produced KMIP AES-GCM wrapped DEK blobs:
 *   u32 iv_len_be, u32 tag_len_be, iv[], tag[], ciphertext[]
 */
struct rgw_kmip_wrapped_dek_parsed {
  uint32_t iv_size = 0;
  uint32_t tag_size = 0;
  int ciphertext_size = 0;
  const char *iv_ptr = nullptr;
  const char *tag_ptr = nullptr;
  const char *ciphertext_ptr = nullptr;
};

/**
 * Validate header and sizes; does not decrypt.
 * On success, iv_ptr/tag_ptr/ciphertext_ptr point into @p raw (must outlive use).
 * @return 0 on success, -EINVAL if malformed
 */
int rgw_kmip_parse_wrapped_dek(const char *raw, size_t len,
                                rgw_kmip_wrapped_dek_parsed *out);
