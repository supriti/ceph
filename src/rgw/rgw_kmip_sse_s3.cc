// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

#include "rgw_kmip_sse_s3.h"
#include "rgw_kmip_client_impl.h"
#include "common/errno.h"
#include "common/async/yield_context.h"
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>


extern "C" {
#include "kmip.h"
#include "kmip_bio.h"
}

#include "include/buffer.h"

#define dout_subsys ceph_subsys_rgw

// KMIP 1.4 §9.1.3.2.19 Revocation Reason enumeration.
// TODO: move to libkmip (src/libkmip) once Ceph-side changes are stable.
enum KmipRevocationReason {
  KMIP_REVOKE_UNSPECIFIED              = 1,
  KMIP_REVOKE_KEY_COMPROMISE           = 2,
  KMIP_REVOKE_CA_COMPROMISE            = 3,
  KMIP_REVOKE_AFFILIATION_CHANGED      = 4,
  KMIP_REVOKE_SUPERSEDED               = 5,
  KMIP_REVOKE_CESSATION_OF_OPERATION   = 6,
  KMIP_REVOKE_PRIVILEGE_WITHDRAWN      = 7,
};

// Global singleton
static RGWKmipSSES3* g_kmip_sse_s3_backend = nullptr;
static ceph::mutex g_kmip_sse_s3_lock = ceph::make_mutex("kmip_sse_s3");

RGWKmipSSES3::RGWKmipSSES3(CephContext* cct)
  : cct(cct) {
}

RGWKmipSSES3::~RGWKmipSSES3() {
  if (rgw_kmip_manager) {
    rgw_kmip_manager->stop();
  }
}

int RGWKmipSSES3::initialize() {
  rgw_kmip_manager = new RGWKMIPManagerImpl(cct);
  if (!rgw_kmip_manager) {
    ldout(cct, 0) << "ERROR: Failed to create KMIP manager" << dendl;
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
  
  ldout(cct, 10) << "KMIP SSE-S3 backend initialized" << dendl;
  return 0;
}

int RGWKmipSSES3::create_bucket_key(const DoutPrefixProvider* dpp,
                                     const std::string& bucket_name,
                                     std::string& kek_id_out,
                                     optional_yield y) {
  struct CreateAndActivateKey : public RGWKMIPTransceiver {
    std::string kek_id;
    std::string name;
    const DoutPrefixProvider* dpp;

    CreateAndActivateKey(CephContext* cct, const std::string& name_in, const DoutPrefixProvider* dpp_in)
      : RGWKMIPTransceiver(cct, RGWKMIPTransceiver::CREATE),
        name(name_in),
        dpp(dpp_in) {}

  int execute(KMIP* ctx, BIO* bio) override {
      ERR_clear_error();
      kmip_init(ctx, NULL, 0, KMIP_1_4);

      if (!kek_id.empty()) {
        return 1;
      }

      // --- Fixed Name Attribute Setup ---
      Attribute name_attr;
      memset(&name_attr, 0, sizeof(name_attr));
      name_attr.type = KMIP_ATTR_NAME;

      // libkmip Name struct initialization
      Name* name_val = (Name*)ctx->calloc_func(ctx->state, 1, sizeof(Name));
      text_string* ts = (text_string*)ctx->calloc_func(ctx->state, 1, sizeof(text_string));
      ts->value = const_cast<char*>(name.c_str());
      ts->size = name.length();

      name_val->value = ts;
      name_val->type = KMIP_NAME_UNINTERPRETED_TEXT_STRING;
      name_attr.value = name_val;

      TemplateAttribute template_attr = {0};
      Attribute attrs[4]; 
      memset(attrs, 0, sizeof(attrs));

      attrs[0] = name_attr;
      
      // Attr 1: AES
      attrs[1].type = KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM;
      attrs[1].value = ctx->calloc_func(ctx->state, 1, sizeof(int32));
      *(int32*)attrs[1].value = KMIP_CRYPTOALG_AES;

      // Attr 2: 256 bits
      attrs[2].type = KMIP_ATTR_CRYPTOGRAPHIC_LENGTH;
      attrs[2].value = ctx->calloc_func(ctx->state, 1, sizeof(int32));
      *(int32*)attrs[2].value = 256;

      // Attr 3: Encrypt+Decrypt
      attrs[3].type = KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK;
      attrs[3].value = ctx->calloc_func(ctx->state, 1, sizeof(int32));
      *(int32*)attrs[3].value = KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT;

      template_attr.attributes = attrs;
      template_attr.attribute_count = 4;

      char* key_id = nullptr;
      int key_id_size = 0;
      int ret = kmip_bio_create_symmetric_key_with_context(ctx, bio, &template_attr, &key_id, &key_id_size);
      
      // Cleanup attr memory (Start from 1 because attrs[0] uses stack structs ts and name_val)
      ctx->free_func(ctx->state, ts);
      ctx->free_func(ctx->state, name_val);
      for (int i = 1; i < 4; i++) {
        if (attrs[i].value) ctx->free_func(ctx->state, attrs[i].value);
      }

      if (ret != KMIP_OK || !key_id) {
        ldpp_dout(this->dpp, 5) << "KMIP create failed: " << ret << dendl;
        ERR_clear_error();
        return -EIO;
      }

      kek_id = std::string(key_id, key_id_size);
      ldpp_dout(this->dpp, 10) << "KMIP created key: " << kek_id << dendl;

      ret = kmip_bio_activate_with_context(ctx, bio, key_id);
      if (ret != KMIP_OK) {
        ldpp_dout(this->dpp, 0) << "KMIP activate failed for " << kek_id
                                << ", destroying orphaned key" << dendl;
        kmip_bio_destroy_symmetric_key_with_context(ctx, bio,
          const_cast<char*>(kek_id.c_str()), kek_id.length());
        kmip_free_buffer(ctx, key_id, key_id_size);
        ERR_clear_error();
        kek_id.clear();
        return -EIO;
      }
      kmip_free_buffer(ctx, key_id, key_id_size);

      return 1;
    }
  };

  if (!rgw_kmip_manager) {
    ldpp_dout(dpp, 0) << "ERROR: KMIP manager not available" << dendl;
    return -EINVAL;
  }

  const std::string key_template = "rgw-kek-" + bucket_name;
  CreateAndActivateKey op(dpp->get_cct(), key_template, dpp);

  int ret = rgw_kmip_manager->add_request(&op);
  if (ret < 0) {
    ldpp_dout(dpp, 0) << "KMIP create key request failed: " << cpp_strerror(ret) << dendl;
    return ret;
  }

  ret = op.wait(dpp, y);
  if (ret < 0) {
    ldpp_dout(dpp, 0) << "Create KEK failed" << dendl;
    return ret;
  }

  kek_id_out = op.kek_id;

  ldpp_dout(dpp, 10) << "KMIP created and activated KEK: " << kek_id_out << dendl;
  return 0;
}


int RGWKmipSSES3::destroy_bucket_key(const DoutPrefixProvider* dpp,
                                      const std::string& kek_id,
                                      optional_yield y) {

  struct DestroyKey : public RGWKMIPTransceiver {
    const std::string& kek_id;
    const DoutPrefixProvider* dpp;

    DestroyKey(CephContext* cct, const std::string& kek, const DoutPrefixProvider* dpp_in)
      : RGWKMIPTransceiver(cct, RGWKMIPTransceiver::DESTROY),
        kek_id(kek),
        dpp(dpp_in) {}

    int execute(KMIP* ctx, BIO* bio) override {
      char* id_ptr = const_cast<char*>(kek_id.c_str());
      int id_len = kek_id.length();

      kmip_init(ctx, NULL, 0, KMIP_1_4);
      ERR_clear_error();

      int revoke_res = kmip_bio_revoke_with_context(
          ctx, bio, id_ptr, id_len, KMIP_REVOKE_CESSATION_OF_OPERATION);
      if (revoke_res != 0) {
        ldpp_dout(this->dpp, 5) << "KMIP revoke KEK " << kek_id
                                << " returned " << revoke_res
                                << " (proceeding to destroy)" << dendl;
        ERR_clear_error();
      }
      int destroy_res = kmip_bio_destroy_symmetric_key_with_context(ctx, bio, id_ptr, id_len);

      if (destroy_res != 0) {
        ldpp_dout(this->dpp, 0) << "KMIP destroy failed: " << destroy_res << dendl;
        ERR_clear_error();
        return -EIO;
      }

      return 1;
    }
  };

  DestroyKey op(dpp->get_cct(), kek_id, dpp);

  int ret = this->rgw_kmip_manager->add_request(&op);
  if (ret < 0) return ret;

  ret = op.wait(dpp, y);
  if (ret < 0) {
    ldpp_dout(dpp, 0) << "Destroy KEK failed: " << cpp_strerror(ret) << dendl;
  } else {
    ldpp_dout(dpp, 10) << "Successfully destroyed KEK: " << kek_id << dendl;
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
  unsigned char dek[32];
  if (RAND_bytes(dek, 32) != 1) {
    ldpp_dout(dpp, 0) << "Failed to generate DEK" << dendl;
    return -EIO;
  }

  plaintext_dek_out.clear();
  plaintext_dek_out.append((char*)dek, 32);

  // Wrap DEK with KMIP
  struct WrapDEK : public RGWKMIPTransceiver {
    const std::string& kek_id;
    const unsigned char* dek_ptr;
    std::string encryption_context;
    bufferlist wrapped_dek;
    const DoutPrefixProvider* dpp;

    WrapDEK(CephContext* cct, const std::string& kek, const unsigned char* dek_ptr, const std::string& ctx, const DoutPrefixProvider* dpp_in)
  : RGWKMIPTransceiver(cct, RGWKMIPTransceiver::ENCRYPT),
    kek_id(kek),
    dek_ptr(dek_ptr),
    encryption_context(ctx),
    dpp(dpp_in) {
      if (!encryption_context.empty() && encryption_context.back() == '\0') {
          encryption_context.pop_back();
      }
    }

    int execute(KMIP* ctx, BIO* bio) override {
      wrapped_dek.clear();
      kmip_init(ctx, NULL, 0, KMIP_1_4);

      CryptographicParameters params;
      memset(&params, 0, sizeof(params));
      kmip_init_cryptographic_parameters(&params);
      params.cryptographic_algorithm = KMIP_CRYPTOALG_AES;
      params.block_cipher_mode = KMIP_BLOCK_GCM;
      params.padding_method = KMIP_PAD_NONE;
      params.random_iv = KMIP_TRUE;
      params.tag_length = 16;
      const uint8_t* aad_ptr = reinterpret_cast<const uint8_t*>(encryption_context.c_str());
      int aad_len = static_cast<int>(encryption_context.length());

      uint8_t* ciphertext = NULL;
      int ciphertext_size = 0;
      uint8_t* iv = NULL;
      int iv_size = 0;
      uint8_t* tag = NULL;
      int tag_size = 0;

      int ret = kmip_bio_encrypt_with_context(
          ctx, bio,
          const_cast<char*>(kek_id.c_str()), (int)kek_id.length(),
          const_cast<uint8_t*>(dek_ptr), 32,
          const_cast<uint8_t*>(aad_ptr), aad_len,
          &params,
          &ciphertext, &ciphertext_size,
          &iv, &iv_size,
          &tag, &tag_size
      );

      if (ret != KMIP_OK) {
        ldpp_dout(dpp, 0) << "KMIP encrypt failed: " << ret << dendl;
        if (ciphertext) { memset(ciphertext, 0, ciphertext_size); ctx->free_func(ctx->state, ciphertext); }
        if (iv) { memset(iv, 0, iv_size); ctx->free_func(ctx->state, iv); }
        if (tag) { memset(tag, 0, tag_size); ctx->free_func(ctx->state, tag); }
        return -EIO;
      }

      uint32_t iv_sz_n = htonl(iv_size);
      uint32_t tag_sz_n = htonl(tag_size);

      wrapped_dek.append((char*)&iv_sz_n, 4);
      wrapped_dek.append((char*)&tag_sz_n, 4);
      wrapped_dek.append((char*)iv, iv_size);
      wrapped_dek.append((char*)tag, tag_size);
      wrapped_dek.append((char*)ciphertext, ciphertext_size);

      memset(ciphertext, 0, ciphertext_size);
      memset(iv, 0, iv_size);
      memset(tag, 0, tag_size);

      if (ciphertext) ctx->free_func(ctx->state, ciphertext);
      if (iv) ctx->free_func(ctx->state, iv);
      if (tag) ctx->free_func(ctx->state, tag);

      ldpp_dout(dpp, 10) << "KMIP encrypt succeeded, wrapped_dek="
                         << wrapped_dek.length() << " bytes" << dendl;
      return 1;
    }

  };

  WrapDEK op(cct, kek_id, dek, encryption_context, dpp);

  int ret = rgw_kmip_manager->add_request(&op);
  if (ret < 0) {
    explicit_bzero(dek, 32);
    return ret;
  }

  ret = op.wait(dpp, y);
  // Always zero sensitive data
  explicit_bzero(dek, 32);
  if (ret < 0) {
    ldpp_dout(dpp, 0) << "KMIP wrap DEK failed" << dendl;
    return ret;
  }

  wrapped_dek_out = std::move(op.wrapped_dek);
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

  struct UnwrapDEK : public RGWKMIPTransceiver {
    const std::string& kek_id;
    const bufferlist& wrapped_dek;
    std::string encryption_context;
    bufferlist plaintext_dek;
    const DoutPrefixProvider* dpp;

    UnwrapDEK(CephContext *cct, const std::string& kek, const bufferlist& wrapped, const std::string& context, const DoutPrefixProvider* dpp_in)
    : RGWKMIPTransceiver(cct, RGWKMIPTransceiver::DECRYPT),
      kek_id(kek),
      wrapped_dek(wrapped),
      encryption_context(context),
      dpp(dpp_in) {}

    int execute(KMIP* ctx, BIO* bio) override {
      kmip_init(ctx, NULL, 0, KMIP_1_4);
      plaintext_dek.clear();

      // Header(8) + IV(12) + Tag(16) + min Ciphertext(16) = 52
      if (wrapped_dek.length() < 52) {
        ldpp_dout(dpp, 0) << "KMIP ERROR: wrapped_dek too small: "
                          << wrapped_dek.length() << " bytes" << dendl;
        return -EINVAL;
      }

      std::vector<char> buffer(wrapped_dek.length());
      wrapped_dek.begin().copy(wrapped_dek.length(), buffer.data());
      const char* raw_data = buffer.data();

      uint32_t iv_size_net, tag_size_net;
      memcpy(&iv_size_net, raw_data, 4);
      memcpy(&tag_size_net, raw_data + 4, 4);
      uint32_t iv_size = ntohl(iv_size_net);
      uint32_t tag_size = ntohl(tag_size_net);

      const uint8_t* iv_ptr = reinterpret_cast<const uint8_t*>(raw_data + 8);
      const uint8_t* tag_ptr = iv_ptr + iv_size;
      const uint8_t* ct_ptr  = tag_ptr + tag_size;
      int ct_size = wrapped_dek.length() - 8 - iv_size - tag_size;

      if (ct_size <= 0 || tag_size != 16) {
        ldpp_dout(dpp, 0) << "KMIP ERROR: invalid wrapped DEK header:"
                          << " iv_size=" << iv_size
                          << " tag_size=" << tag_size
                          << " ct_size=" << ct_size << dendl;
        return -EINVAL;
      }

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

      int ret = kmip_bio_decrypt_with_context(
        ctx, bio,
        const_cast<char*>(kek_id.c_str()), (int)kek_id.length(),
        const_cast<uint8_t*>(ct_ptr), ct_size,
        const_cast<uint8_t*>(aad_ptr), aad_len,
        const_cast<uint8_t*>(iv_ptr), iv_size,
        const_cast<uint8_t*>(tag_ptr), tag_size,
        &params,
        &plaintext, &plaintext_size
      );

      if (ret != KMIP_OK || plaintext_size != 32) {
        ldpp_dout(dpp, 0) << "KMIP decrypt failed: ret=" << ret
                          << " plaintext_size=" << plaintext_size << dendl;
        if (plaintext) {
          kmip_free_buffer(ctx, plaintext, plaintext_size);
        }
        return -EIO;
      }

      plaintext_dek.append(reinterpret_cast<char*>(plaintext), 32);
      ::ceph::crypto::zeroize_for_security(plaintext, plaintext_size);
      kmip_free_buffer(ctx, plaintext, plaintext_size);
      return 1;
    }
  };

  UnwrapDEK op(cct, kek_id, wrapped_dek, encryption_context, dpp);

  int ret = this->rgw_kmip_manager->add_request(&op);
  if (ret < 0) return ret;

  ret = op.wait(dpp, y);
  if (ret < 0) {
    ldpp_dout(dpp, 0) << "Unwrap DEK failed: " << cpp_strerror(ret) << dendl;
    return ret;
  }

  plaintext_dek_out = std::move(op.plaintext_dek);
  ldpp_dout(dpp, 10) << "Successfully unwrapped DEK ("
                      << plaintext_dek_out.length() << " bytes)" << dendl;
  return 0;
}

RGWKmipSseS3Backend* get_kmip_sse_s3_backend(CephContext* cct) {
  std::unique_lock l{g_kmip_sse_s3_lock};

  if (!g_kmip_sse_s3_backend) {
    g_kmip_sse_s3_backend = new RGWKmipSSES3(cct);
    int ret = g_kmip_sse_s3_backend->initialize();
    if (ret < 0) {
      ldout(cct, 0) << "Failed to initialize KMIP SSE-S3 backend" << dendl;
      delete g_kmip_sse_s3_backend;
      g_kmip_sse_s3_backend = nullptr;
    }
  }
  return g_kmip_sse_s3_backend;
}

void cleanup_kmip_sse_s3_backend() {
  std::unique_lock l{g_kmip_sse_s3_lock};
  if (g_kmip_sse_s3_backend) {
    delete g_kmip_sse_s3_backend;
    g_kmip_sse_s3_backend = nullptr;
  }
}
