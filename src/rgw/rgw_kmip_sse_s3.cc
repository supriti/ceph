// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

#include "rgw_kmip_sse_s3.h"
#include "rgw_kmip_client_impl.h"
#include "rgw_kmip_wrapped_dek.h"
#include "common/errno.h"
#include "common/async/yield_context.h"
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <new>

extern "C" {
#include "kmip.h"
#include "kmip_bio.h"
}

#include "include/buffer.h"

#define dout_subsys ceph_subsys_rgw

// AES-256 key: 32 bytes / 256 bits. DEKs and KEK-wrapped outputs must match.
static constexpr int KMIP_DEK_SIZE = 32;
static RGWKmipSSES3* g_kmip_sse_s3_backend = nullptr;
static ceph::mutex g_kmip_sse_s3_lock = ceph::make_mutex("kmip_sse_s3");

RGWKmipSSES3::RGWKmipSSES3(CephContext* cct)
  : cct(cct) {
}

int RGWKmipSSES3::initialize() {
  if (rgw_kmip_manager) {
    ldout(cct, 10) << "KMIP SSE-S3 reusing global KMIP manager" << dendl;
    return 0;
  }

  rgw_kmip_manager = new (std::nothrow) RGWKMIPManagerImpl(cct);
  if (!rgw_kmip_manager) {
    ldout(cct, 0) << "ERROR: Failed to create KMIP manager (alloc)" << dendl;
    return -ENOMEM;
  }

  int ret = rgw_kmip_manager->start();
  if (ret < 0) {
    ldout(cct, 0) << "ERROR: Failed to start KMIP manager: "
                  << cpp_strerror(ret) << dendl;
    delete rgw_kmip_manager;
    rgw_kmip_manager = nullptr;
    return ret;
  }

  ldout(cct, 10) << "KMIP SSE-S3 backend initialized standalone KMIP manager" << dendl;
  return 0;
}

int RGWKmipSSES3::create_bucket_key(const DoutPrefixProvider* dpp,
                                     const std::string& bucket_name,
                                     std::string& kek_id_out,
                                     optional_yield y) {
  if (!rgw_kmip_manager) {
    ldpp_dout(dpp, 0) << "ERROR: KMIP manager not available" << dendl;
    return -EINVAL;
  }

  /* Key name is derived from bucket name only. If a bucket is deleted and
   * recreated with the same name, the KMIP server may still hold a key with
   * this name; create a unique bucket name */
  const std::string key_template = "rgw-kek-" + bucket_name;

  int ret = rgw_kmip_manager->execute_fn(dpp, y,
      [&](KMIP* ctx, BIO* bio) -> int {
    ERR_clear_error();
    /* Pooled KMIP ctx is owned by the handle; reset per op (kmip_init would tear down credentials). */
    kmip_reset(ctx);

    Attribute name_attr;
    memset(&name_attr, 0, sizeof(name_attr));
    name_attr.type = KMIP_ATTR_NAME;

    // libkmip Name struct: heap-allocated so libkmip can reference them during encoding.
    Name* name_val = (Name*)ctx->calloc_func(ctx->state, 1, sizeof(Name));
    text_string* ts = (text_string*)ctx->calloc_func(ctx->state, 1, sizeof(text_string));
    if (!name_val || !ts) {
      if (ts)       ctx->free_func(ctx->state, ts);
      if (name_val) ctx->free_func(ctx->state, name_val);
      return -ENOMEM;
    }
    ts->value = const_cast<char*>(key_template.c_str());
    ts->size = key_template.length();

    name_val->value = ts;
    name_val->type = KMIP_NAME_UNINTERPRETED_TEXT_STRING;
    name_attr.value = name_val;

    TemplateAttribute template_attr = {0};
    Attribute attrs[4];
    memset(attrs, 0, sizeof(attrs));

    attrs[0] = name_attr;

    attrs[1].type = KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM;
    attrs[1].value = ctx->calloc_func(ctx->state, 1, sizeof(int32));
    attrs[2].type = KMIP_ATTR_CRYPTOGRAPHIC_LENGTH;
    attrs[2].value = ctx->calloc_func(ctx->state, 1, sizeof(int32));
    attrs[3].type = KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK;
    attrs[3].value = ctx->calloc_func(ctx->state, 1, sizeof(int32));

    if (!attrs[1].value || !attrs[2].value || !attrs[3].value) {
      ctx->free_func(ctx->state, ts);
      ctx->free_func(ctx->state, name_val);
      for (int i = 1; i < 4; i++) {
        if (attrs[i].value) ctx->free_func(ctx->state, attrs[i].value);
      }
      return -ENOMEM;
    }
    *(int32*)attrs[1].value = KMIP_CRYPTOALG_AES;
    *(int32*)attrs[2].value = 256;
    *(int32*)attrs[3].value = KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT;

    template_attr.attributes = attrs;
    template_attr.attribute_count = 4;

    char* key_id = nullptr;
    int key_id_size = 0;
    int r = kmip_bio_create_symmetric_key_with_context(ctx, bio, &template_attr, &key_id, &key_id_size);

    // attrs[0].value (name_val, ts) freed separately; attrs[1-3] freed in loop.
    ctx->free_func(ctx->state, ts);
    ctx->free_func(ctx->state, name_val);
    for (int i = 1; i < 4; i++) {
      if (attrs[i].value) ctx->free_func(ctx->state, attrs[i].value);
    }

    if (r != KMIP_OK || !key_id) {
      ldpp_dout(dpp, 5) << "KMIP create failed: " << r << dendl;
      ERR_clear_error();
      return -EIO;
    }

    kek_id_out = std::string(key_id, key_id_size);
    ldpp_dout(dpp, 10) << "KMIP created key id_len=" << kek_id_out.length() << dendl;

    r = kmip_bio_activate_with_context(ctx, bio, key_id);
    if (r != KMIP_OK) {
      ldpp_dout(dpp, 0) << "KMIP activate failed id_len=" << kek_id_out.length()
                        << ", destroying orphaned key" << dendl;
      kmip_bio_destroy_symmetric_key_with_context(ctx, bio,
        const_cast<char*>(kek_id_out.c_str()), kek_id_out.length());
      ctx->free_func(ctx->state, key_id);
      ERR_clear_error();
      kek_id_out.clear();
      return -EIO;
    }
    ctx->free_func(ctx->state, key_id);
    return 0;
  });

  if (ret < 0) {
    ldpp_dout(dpp, 0) << "Create KEK failed" << dendl;
    return ret;
  }

  ldpp_dout(dpp, 10) << "KMIP created and activated KEK id_len=" << kek_id_out.length()
                     << dendl;
  return 0;
}


int RGWKmipSSES3::destroy_bucket_key(const DoutPrefixProvider* dpp,
                                      const std::string& kek_id,
                                      optional_yield y) {
  int ret = rgw_kmip_manager->execute_fn(dpp, y,
      [&](KMIP* ctx, BIO* bio) -> int {
    char* id_ptr = const_cast<char*>(kek_id.c_str());
    int id_len = kek_id.length();

    kmip_reset(ctx);
    ERR_clear_error();

    int revoke_res = kmip_bio_revoke_with_context(
        ctx, bio, id_ptr, id_len, KMIP_REVOCATION_CESSATION_OF_OPERATION);
    if (revoke_res != 0) {
      ldpp_dout(dpp, 0) << "KMIP revoke KEK id_len=" << kek_id.length()
                        << " returned " << revoke_res
                        << " (proceeding to destroy)" << dendl;
      ERR_clear_error();
    }
    int destroy_res = kmip_bio_destroy_symmetric_key_with_context(ctx, bio, id_ptr, id_len);
    if (destroy_res != 0) {
      ldpp_dout(dpp, 0) << "KMIP destroy failed: " << destroy_res << dendl;
      ERR_clear_error();
      return -EIO;
    }
    return 0;
  });

  if (ret < 0) {
    ldpp_dout(dpp, 0) << "Destroy KEK failed: " << cpp_strerror(ret) << dendl;
  } else {
    ldpp_dout(dpp, 10) << "Successfully destroyed KEK id_len=" << kek_id.length()
                       << dendl;
  }
  return ret;
}


int RGWKmipSSES3::generate_and_wrap_dek(const DoutPrefixProvider* dpp,
                                         const std::string& kek_id,
                                         const std::string& encryption_context,
                                         bufferlist& plaintext_dek_out,
                                         bufferlist& wrapped_dek_out,
                                         optional_yield y) {
  // Generate random DEK
  unsigned char dek[KMIP_DEK_SIZE];
  if (RAND_bytes(dek, KMIP_DEK_SIZE) != 1) {
    ldpp_dout(dpp, 0) << "Failed to generate DEK" << dendl;
    return -EIO;
  }

  plaintext_dek_out.clear();

  /* Strip trailing NUL if callers pass null-terminated strings as std::string.
   * AAD must be identical at wrap and unwrap time; stripping here ensures
   * consistent behaviour if the caller is inconsistent. */
  std::string aad = encryption_context;
  if (!aad.empty() && aad.back() == '\0') {
    aad.pop_back();
  }

  int ret = rgw_kmip_manager->execute_fn(dpp, y,
      [&](KMIP* ctx, BIO* bio) -> int {
    wrapped_dek_out.clear();
    /* kmip_bio_encrypt_with_context resets ctx at entry */

    /* Zeroize a KMIP-allocated buffer and free it back to the KMIP allocator. */
    auto kmip_zeroize_free = [ctx](uint8_t* buf, int sz) {
      if (buf) {
        ::ceph::crypto::zeroize_for_security(buf, sz);
        ctx->free_func(ctx->state, buf);
      }
    };

    CryptographicParameters params;
    memset(&params, 0, sizeof(params));
    kmip_init_cryptographic_parameters(&params);
    params.cryptographic_algorithm = KMIP_CRYPTOALG_AES;
    params.block_cipher_mode = KMIP_BLOCK_GCM;
    params.padding_method = KMIP_PAD_NONE;
    params.random_iv = KMIP_TRUE;
    params.tag_length = 16;
    const uint8_t* aad_ptr = reinterpret_cast<const uint8_t*>(aad.c_str());
    int aad_len = static_cast<int>(aad.length());

    uint8_t* ciphertext = NULL;
    int ciphertext_size = 0;
    uint8_t* iv = NULL;
    int iv_size = 0;
    uint8_t* tag = NULL;
    int tag_size = 0;

    int r = kmip_bio_encrypt_with_context(
        ctx, bio,
        const_cast<char*>(kek_id.c_str()), (int)kek_id.length(),
        const_cast<uint8_t*>(dek), KMIP_DEK_SIZE,
        const_cast<uint8_t*>(aad_ptr), aad_len,
        &params,
        &ciphertext, &ciphertext_size,
        &iv, &iv_size,
        &tag, &tag_size
    );

    if (r != KMIP_OK) {
      ldpp_dout(dpp, 0) << "KMIP encrypt failed: " << r << dendl;
      kmip_zeroize_free(ciphertext, ciphertext_size);
      kmip_zeroize_free(iv, iv_size);
      kmip_zeroize_free(tag, tag_size);
      return -EIO;
    }

    uint32_t iv_sz_n = htonl(iv_size);
    uint32_t tag_sz_n = htonl(tag_size);

    wrapped_dek_out.append((char*)&iv_sz_n, 4);
    wrapped_dek_out.append((char*)&tag_sz_n, 4);
    wrapped_dek_out.append((char*)iv, iv_size);
    wrapped_dek_out.append((char*)tag, tag_size);
    wrapped_dek_out.append((char*)ciphertext, ciphertext_size);

    kmip_zeroize_free(ciphertext, ciphertext_size);
    kmip_zeroize_free(iv, iv_size);
    kmip_zeroize_free(tag, tag_size);

    ldpp_dout(dpp, 10) << "KMIP encrypt succeeded, wrapped_dek="
                       << wrapped_dek_out.length() << " bytes" << dendl;
    return 0;
  });

  if (ret < 0) {
    explicit_bzero(dek, KMIP_DEK_SIZE);
    ldpp_dout(dpp, 0) << "KMIP wrap DEK failed" << dendl;
    return ret;
  }

  plaintext_dek_out.append((char*)dek, KMIP_DEK_SIZE);
  explicit_bzero(dek, KMIP_DEK_SIZE);

  ldpp_dout(dpp, 10) << "KMIP wrapped DEK, size=" << wrapped_dek_out.length() << dendl;
  return 0;
}

int RGWKmipSSES3::unwrap_dek(const DoutPrefixProvider* dpp,
                              const std::string& kek_id,
                              const bufferlist& wrapped_dek,
                              const std::string& encryption_context,
                              bufferlist& plaintext_dek_out,
                              optional_yield y) {
  if (wrapped_dek.length() < 8) {
    ldpp_dout(dpp, 0) << "KMIP ERROR: Metadata size mismatch" << dendl;
    return -EINVAL;
  }

  int ret = rgw_kmip_manager->execute_fn(dpp, y,
      [&](KMIP* ctx, BIO* bio) -> int {
    /* kmip_bio_decrypt_with_context resets ctx at entry */
    plaintext_dek_out.clear();

    std::vector<char> buffer(wrapped_dek.length());
    wrapped_dek.begin().copy(wrapped_dek.length(), buffer.data());
    rgw_kmip_wrapped_dek_parsed layout{};
    if (rgw_kmip_parse_wrapped_dek(buffer.data(), buffer.size(), &layout) != 0) {
      ldpp_dout(dpp, 0) << "KMIP ERROR: invalid wrapped DEK layout len="
                        << buffer.size() << dendl;
      return -EINVAL;
    }

    const uint8_t* iv_ptr = reinterpret_cast<const uint8_t*>(layout.iv_ptr);
    const uint8_t* tag_ptr = reinterpret_cast<const uint8_t*>(layout.tag_ptr);
    const uint8_t* ct_ptr = reinterpret_cast<const uint8_t*>(layout.ciphertext_ptr);
    const int ct_size = static_cast<int>(layout.ciphertext_size);

    CryptographicParameters params;
    memset(&params, 0, sizeof(params));
    kmip_init_cryptographic_parameters(&params);
    params.cryptographic_algorithm = KMIP_CRYPTOALG_AES;
    params.block_cipher_mode = KMIP_BLOCK_GCM;
    params.padding_method = KMIP_PAD_NONE;
    params.tag_length = 16;
    const uint8_t* aad_ptr = reinterpret_cast<const uint8_t*>(encryption_context.c_str());
    int aad_len = static_cast<int>(encryption_context.length());

    uint8_t* plaintext = nullptr;
    int32_t plaintext_size = 0;

    int r = kmip_bio_decrypt_with_context(
      ctx, bio,
      const_cast<char*>(kek_id.c_str()), (int)kek_id.length(),
      const_cast<uint8_t*>(ct_ptr), ct_size,
      const_cast<uint8_t*>(aad_ptr), aad_len,
      const_cast<uint8_t*>(iv_ptr), static_cast<int>(layout.iv_size),
      const_cast<uint8_t*>(tag_ptr), static_cast<int>(layout.tag_size),
      &params,
      &plaintext, &plaintext_size
    );

    if (r != KMIP_OK || plaintext_size != KMIP_DEK_SIZE) {
      ldpp_dout(dpp, 0) << "KMIP decrypt failed: ret=" << r
                        << " plaintext_size=" << plaintext_size << dendl;
      if (plaintext) {
        ::ceph::crypto::zeroize_for_security(plaintext, plaintext_size);
        ctx->free_func(ctx->state, plaintext);
      }
      return -EIO;
    }

    plaintext_dek_out.append(reinterpret_cast<char*>(plaintext), KMIP_DEK_SIZE);
    ::ceph::crypto::zeroize_for_security(plaintext, plaintext_size);
    ctx->free_func(ctx->state, plaintext);
    return 0;
  });

  if (ret < 0) {
    ldpp_dout(dpp, 0) << "Unwrap DEK failed: " << cpp_strerror(ret) << dendl;
    return ret;
  }

  ldpp_dout(dpp, 10) << "Successfully unwrapped DEK ("
                      << plaintext_dek_out.length() << " bytes)" << dendl;
  return 0;
}

RGWKmipSseS3Backend* get_kmip_sse_s3_backend(CephContext* cct) {
  std::unique_lock l{g_kmip_sse_s3_lock};

  if (!g_kmip_sse_s3_backend) {
    g_kmip_sse_s3_backend = new (std::nothrow) RGWKmipSSES3(cct);
    if (!g_kmip_sse_s3_backend) {
      ldout(cct, 0) << "Failed to allocate KMIP SSE-S3 backend" << dendl;
      return nullptr;
    }
    int ret = g_kmip_sse_s3_backend->initialize();
    if (ret < 0) {
      ldout(cct, 0) << "Failed to initialize KMIP SSE-S3 backend" << dendl;
      delete g_kmip_sse_s3_backend;
      g_kmip_sse_s3_backend = nullptr;
    }
  }
  return g_kmip_sse_s3_backend;
}

void cleanup_kmip_sse_s3_backend()
{
  std::unique_lock l{g_kmip_sse_s3_lock};
  if (g_kmip_sse_s3_backend) {
    delete g_kmip_sse_s3_backend;
    g_kmip_sse_s3_backend = nullptr;
  }
}
