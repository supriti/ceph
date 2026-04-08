// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#include "rgw_kmip_wrapped_dek.h"

#include <arpa/inet.h>
#include <cstring>
#include <errno.h>

int rgw_kmip_parse_wrapped_dek(const char *raw, size_t len,
                               rgw_kmip_wrapped_dek_parsed *out)
{
  if (!out || !raw) {
    return -EINVAL;
  }
  *out = rgw_kmip_wrapped_dek_parsed{};
  if (len < 52) {
    return -EINVAL;
  }

  uint32_t iv_size_net;
  uint32_t tag_size_net;
  memcpy(&iv_size_net, raw, 4);
  memcpy(&tag_size_net, raw + 4, 4);
  const uint32_t iv_size = ntohl(iv_size_net);
  const uint32_t tag_size = ntohl(tag_size_net);

  const size_t need = static_cast<size_t>(8) + iv_size + tag_size;
  if (need > len || tag_size != 16) {
    return -EINVAL;
  }
  const size_t ct_size = len - 8 - iv_size - tag_size;
  if (ct_size == 0 || ct_size > UINT32_MAX) {
    return -EINVAL;
  }

  out->iv_size = iv_size;
  out->tag_size = tag_size;
  out->ciphertext_size = static_cast<uint32_t>(ct_size);
  out->iv_ptr = raw + 8;
  out->tag_ptr = out->iv_ptr + iv_size;
  out->ciphertext_ptr = out->tag_ptr + tag_size;
  return 0;
}
