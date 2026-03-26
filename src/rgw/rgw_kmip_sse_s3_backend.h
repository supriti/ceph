// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#pragma once

#include "rgw_common.h"
#include "include/buffer.h"

class DoutPrefixProvider;

/**
 * KMIP-backed SSE-S3: KEK lifecycle and DEK wrap/unwrap.
 *
 * Callers (e.g. rgw_kms) should use this interface so tests can substitute
 * a mock without linking the full RGWKmipSSES3 / TLS / libkmip stack.
 */
class RGWKmipSseS3Backend {
public:
  virtual ~RGWKmipSseS3Backend() = default;

  virtual int create_bucket_key(const DoutPrefixProvider* dpp,
                                const std::string& bucket_name,
                                std::string& kek_id_out,
                                optional_yield y) = 0;

  virtual int destroy_bucket_key(const DoutPrefixProvider* dpp,
                                 const std::string& kek_id,
                                 optional_yield y) = 0;

  virtual int generate_and_wrap_dek(const DoutPrefixProvider* dpp,
                                    const std::string& kek_id,
                                    const std::string& encryption_context,
                                    bufferlist& plaintext_dek_out,
                                    bufferlist& wrapped_dek_out,
                                    optional_yield y) = 0;

  virtual int unwrap_dek(const DoutPrefixProvider* dpp,
                         const std::string& kek_id,
                         const bufferlist& wrapped_dek,
                         const std::string& encryption_context,
                         bufferlist& plaintext_dek_out,
                         optional_yield y) = 0;
};
