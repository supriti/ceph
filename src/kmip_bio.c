/* Copyright (c) 2018 The Johns Hopkins University/Applied Physics Laboratory
 * All Rights Reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include <openssl/ssl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "kmip.h"
#include "kmip_memset.h"
#include "kmip_io.h"
#include "kmip_bio.h"

/*
OpenSSH BIO API
*/

int kmip_bio_create_symmetric_key(BIO *bio,
                                  TemplateAttribute *template_attribute,
                                  char **id, int *id_size)
{
    if(bio == NULL || template_attribute == NULL || id == NULL || id_size == NULL)
        return(KMIP_ARG_INVALID);
    
    /* Set up the KMIP context and the initial encoding buffer. */
    KMIP ctx = {0};
    kmip_init(&ctx, NULL, 0, KMIP_1_0);
    
    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;
    
    uint8 *encoding = ctx.calloc_func(ctx.state, buffer_blocks,
                                      buffer_block_size);
    if(encoding == NULL)
    {
        kmip_destroy(&ctx);
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    kmip_set_buffer(&ctx, encoding, buffer_total_size);
    
    /* Build the request message. */
    ProtocolVersion pv = {0};
    kmip_init_protocol_version(&pv, ctx.version);
    
    RequestHeader rh = {0};
    kmip_init_request_header(&rh);
    
    rh.protocol_version = &pv;
    rh.maximum_response_size = ctx.max_message_size;
    rh.time_stamp = time(NULL);
    rh.batch_count = 1;
    
    CreateRequestPayload crp = {0};
    crp.object_type = KMIP_OBJTYPE_SYMMETRIC_KEY;
    crp.template_attribute = template_attribute;
    
    RequestBatchItem rbi = {0};
    kmip_init_request_batch_item(&rbi);
    rbi.operation = KMIP_OP_CREATE;
    rbi.request_payload = &crp;
    
    RequestMessage rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;
    
    /* Encode the request message. Dynamically resize the encoding buffer */
    /* if it's not big enough. Once encoding succeeds, send the request   */
    /* message.                                                           */
    int encode_result = kmip_encode_request_message(&ctx, &rm);
    while(encode_result == KMIP_ERROR_BUFFER_FULL)
    {
        kmip_reset(&ctx);
        ctx.free_func(ctx.state, encoding);
        
        buffer_blocks += 1;
        buffer_total_size = buffer_blocks * buffer_block_size;
        
        encoding = ctx.calloc_func(ctx.state, buffer_blocks,
                                   buffer_block_size);
        if(encoding == NULL)
        {
            kmip_destroy(&ctx);
            return(KMIP_MEMORY_ALLOC_FAILED);
        }
        
        kmip_set_buffer(
            &ctx,
            encoding,
            buffer_total_size);
        encode_result = kmip_encode_request_message(&ctx, &rm);
    }
    
    if(encode_result != KMIP_OK)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(encode_result);
    }
    
    int sent = BIO_write(bio, ctx.buffer, ctx.index - ctx.buffer);
    if(sent != ctx.index - ctx.buffer)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_free_buffer(&ctx, encoding, buffer_total_size);
    encoding = NULL;
    
    /* Read the response message. Dynamically resize the encoding buffer  */
    /* to align with the message size advertised by the message encoding. */
    /* Reject the message if the message size is too large.               */
    buffer_blocks = 1;
    buffer_block_size = 8;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    encoding = ctx.calloc_func(ctx.state, buffer_blocks, buffer_block_size);
    if(encoding == NULL)
    {
        kmip_destroy(&ctx);
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    
    int recv = BIO_read(bio, encoding, buffer_total_size);
    if((size_t)recv != buffer_total_size)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(&ctx, encoding, buffer_total_size);
    ctx.index += 4;
    int length = 0;
    
    kmip_decode_int32_be(&ctx, &length);
    kmip_rewind(&ctx);
    if(length > ctx.max_message_size)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_EXCEED_MAX_MESSAGE_SIZE);
    }
    
    kmip_set_buffer(&ctx, NULL, 0);
    uint8 *extended = ctx.realloc_func(ctx.state, encoding, buffer_total_size + length);
    if(encoding != extended)
        encoding = extended;
    ctx.memset_func(encoding + buffer_total_size, 0, length);
    
    buffer_block_size += length;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    recv = BIO_read(bio, encoding + 8, length);
    if(recv != length)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(&ctx, encoding, buffer_block_size);
    
    /* Decode the response message and retrieve the operation results. */
    ResponseMessage resp_m = {0};
    int decode_result = kmip_decode_response_message(&ctx, &resp_m);
    if(decode_result != KMIP_OK)
    {
        kmip_free_response_message(&ctx, &resp_m);
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(decode_result);
    }

    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        kmip_free_response_message(&ctx, &resp_m);
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_MALFORMED_RESPONSE);
    }
    
    ResponseBatchItem resp_item = resp_m.batch_items[0];
    enum result_status result = resp_item.result_status;

    if(result != KMIP_STATUS_SUCCESS)
    {
        kmip_free_response_message(&ctx, &resp_m);
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(&ctx, NULL, 0);
        kmip_destroy(&ctx);
        return(result);
    }
    
    CreateResponsePayload *pld = (CreateResponsePayload *)resp_item.response_payload;
    TextString *unique_identifier = pld->unique_identifier;
    
    /* KMIP text strings are not null-terminated by default. Add an extra */
    /* character to the end of the UUID copy to make space for the null   */
    /* terminator.                                                        */
    char *result_id = ctx.calloc_func(
        ctx.state,
        1,
        unique_identifier->size + 1);
    *id_size = unique_identifier->size;
    for(int i = 0; i < *id_size; i++)
        result_id[i] = unique_identifier->value[i];
    *id = result_id;
    
    /* Clean up the response message, the encoding buffer, and the KMIP */
    /* context. */
    kmip_free_response_message(&ctx, &resp_m);
    kmip_free_buffer(&ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(&ctx, NULL, 0);
    kmip_destroy(&ctx);
    
    return(result);
}

int kmip_bio_destroy_symmetric_key(BIO *bio, char *uuid, int uuid_size)
{
    if(bio == NULL || uuid == NULL || uuid_size <= 0)
    {
        return(KMIP_ARG_INVALID);
    }
    
    /* Set up the KMIP context and the initial encoding buffer. */
    KMIP ctx = {0};
    kmip_init(&ctx, NULL, 0, KMIP_1_0);
    
    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;
    
    uint8 *encoding = ctx.calloc_func(ctx.state, buffer_blocks,
                                      buffer_block_size);
    if(encoding == NULL)
    {
        kmip_destroy(&ctx);
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    kmip_set_buffer(&ctx, encoding, buffer_total_size);
    
    /* Build the request message. */
    ProtocolVersion pv = {0};
    kmip_init_protocol_version(&pv, ctx.version);
    
    RequestHeader rh = {0};
    kmip_init_request_header(&rh);
    
    rh.protocol_version = &pv;
    rh.maximum_response_size = ctx.max_message_size;
    rh.time_stamp = time(NULL);
    rh.batch_count = 1;
    
    TextString id = {0};
    id.value = uuid;
    id.size = uuid_size;
    
    DestroyRequestPayload drp = {0};
    drp.unique_identifier = &id;
    
    RequestBatchItem rbi = {0};
    kmip_init_request_batch_item(&rbi);
    rbi.operation = KMIP_OP_DESTROY;
    rbi.request_payload = &drp;
    
    RequestMessage rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;
    
    /* Encode the request message. Dynamically resize the encoding buffer */
    /* if it's not big enough. Once encoding succeeds, send the request   */
    /* message.                                                           */
    int encode_result = kmip_encode_request_message(&ctx, &rm);
    while(encode_result == KMIP_ERROR_BUFFER_FULL)
    {
        kmip_reset(&ctx);
        ctx.free_func(ctx.state, encoding);
        
        buffer_blocks += 1;
        buffer_total_size = buffer_blocks * buffer_block_size;
        
        encoding = ctx.calloc_func(ctx.state, buffer_blocks,
                                   buffer_block_size);
        if(encoding == NULL)
        {
            kmip_destroy(&ctx);
            return(KMIP_MEMORY_ALLOC_FAILED);
        }
        
        kmip_set_buffer(
            &ctx,
            encoding,
            buffer_total_size);
        encode_result = kmip_encode_request_message(&ctx, &rm);
    }
    
    if(encode_result != KMIP_OK)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(encode_result);
    }
    
    int sent = BIO_write(bio, ctx.buffer, ctx.index - ctx.buffer);
    if(sent != ctx.index - ctx.buffer)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_free_buffer(&ctx, encoding, buffer_total_size);
    encoding = NULL;
    
    /* Read the response message. Dynamically resize the encoding buffer  */
    /* to align with the message size advertised by the message encoding. */
    /* Reject the message if the message size is too large.               */
    buffer_blocks = 1;
    buffer_block_size = 8;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    encoding = ctx.calloc_func(ctx.state, buffer_blocks, buffer_block_size);
    if(encoding == NULL)
    {
        kmip_destroy(&ctx);
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    
    int recv = BIO_read(bio, encoding, buffer_total_size);
    if((size_t)recv != buffer_total_size)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(&ctx, encoding, buffer_total_size);
    ctx.index += 4;
    int length = 0;
    
    kmip_decode_int32_be(&ctx, &length);
    kmip_rewind(&ctx);
    if(length > ctx.max_message_size)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_EXCEED_MAX_MESSAGE_SIZE);
    }
    
    kmip_set_buffer(&ctx, NULL, 0);
    uint8 *extended = ctx.realloc_func(ctx.state, encoding, buffer_total_size + length);
    if(extended == NULL)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    else
    {
        encoding = extended;
        extended = NULL;
    }
    
    ctx.memset_func(encoding + buffer_total_size, 0, length);
    
    buffer_block_size += length;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    recv = BIO_read(bio, encoding + 8, length);
    if(recv != length)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(&ctx, encoding, buffer_block_size);
    
    /* Decode the response message and retrieve the operation result status. */
    ResponseMessage resp_m = {0};
    int decode_result = kmip_decode_response_message(&ctx, &resp_m);
    if(decode_result != KMIP_OK)
    {
        kmip_free_response_message(&ctx, &resp_m);
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(decode_result);
    }

    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        kmip_free_response_message(&ctx, &resp_m);
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_MALFORMED_RESPONSE);
    }
    
    ResponseBatchItem resp_item = resp_m.batch_items[0];
    enum result_status result = resp_item.result_status;
    
    /* Clean up the response message, the encoding buffer, and the KMIP */
    /* context. */
    kmip_free_response_message(&ctx, &resp_m);
    kmip_free_buffer(&ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(&ctx, NULL, 0);
    kmip_destroy(&ctx);
    
    return(result);
}

int kmip_bio_get_symmetric_key(BIO *bio,
                               char *id, int id_size,
                               char **key, int *key_size)
{
    if(bio == NULL || id == NULL || id_size <= 0 || key == NULL || key_size == NULL)
    {
        return(KMIP_ARG_INVALID);
    }
    
    /* Set up the KMIP context and the initial encoding buffer. */
    KMIP ctx = {0};
    kmip_init(&ctx, NULL, 0, KMIP_1_0);
    
    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;
    
    uint8 *encoding = ctx.calloc_func(ctx.state, buffer_blocks,
                                      buffer_block_size);
    if(encoding == NULL)
    {
        kmip_destroy(&ctx);
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    kmip_set_buffer(&ctx, encoding, buffer_total_size);
    
    /* Build the request message. */
    ProtocolVersion pv = {0};
    kmip_init_protocol_version(&pv, ctx.version);
    
    RequestHeader rh = {0};
    kmip_init_request_header(&rh);
    
    rh.protocol_version = &pv;
    rh.maximum_response_size = ctx.max_message_size;
    rh.time_stamp = time(NULL);
    rh.batch_count = 1;
    
    TextString uuid = {0};
    uuid.value = id;
    uuid.size = id_size;
    
    GetRequestPayload grp = {0};
    grp.unique_identifier = &uuid;
    
    RequestBatchItem rbi = {0};
    kmip_init_request_batch_item(&rbi);
    rbi.operation = KMIP_OP_GET;
    rbi.request_payload = &grp;
    
    RequestMessage rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;
    
    /* Encode the request message. Dynamically resize the encoding buffer */
    /* if it's not big enough. Once encoding succeeds, send the request   */
    /* message.                                                           */
    int encode_result = kmip_encode_request_message(&ctx, &rm);
    while(encode_result == KMIP_ERROR_BUFFER_FULL)
    {
        kmip_reset(&ctx);
        ctx.free_func(ctx.state, encoding);
        
        buffer_blocks += 1;
        buffer_total_size = buffer_blocks * buffer_block_size;
        
        encoding = ctx.calloc_func(ctx.state, buffer_blocks,
                                   buffer_block_size);
        if(encoding == NULL)
        {
            kmip_destroy(&ctx);
            return(KMIP_MEMORY_ALLOC_FAILED);
        }
        
        kmip_set_buffer(
            &ctx,
            encoding,
            buffer_total_size);
        encode_result = kmip_encode_request_message(&ctx, &rm);
    }
    
    if(encode_result != KMIP_OK)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(encode_result);
    }
    
    int sent = BIO_write(bio, ctx.buffer, ctx.index - ctx.buffer);
    if(sent != ctx.index - ctx.buffer)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_free_buffer(&ctx, encoding, buffer_total_size);
    encoding = NULL;
    
    /* Read the response message. Dynamically resize the encoding buffer  */
    /* to align with the message size advertised by the message encoding. */
    /* Reject the message if the message size is too large.               */
    buffer_blocks = 1;
    buffer_block_size = 8;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    encoding = ctx.calloc_func(ctx.state, buffer_blocks, buffer_block_size);
    if(encoding == NULL)
    {
        kmip_destroy(&ctx);
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    
    int recv = BIO_read(bio, encoding, buffer_total_size);
    if((size_t)recv != buffer_total_size)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(&ctx, encoding, buffer_total_size);
    ctx.index += 4;
    int length = 0;
    
    kmip_decode_int32_be(&ctx, &length);
    kmip_rewind(&ctx);
    if(length > ctx.max_message_size)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_EXCEED_MAX_MESSAGE_SIZE);
    }
    
    kmip_set_buffer(&ctx, NULL, 0);
    uint8 *extended = ctx.realloc_func(ctx.state, encoding, buffer_total_size + length);
    if(encoding != extended)
    {
        encoding = extended;
    }
    ctx.memset_func(encoding + buffer_total_size, 0, length);
    
    buffer_block_size += length;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    recv = BIO_read(bio, encoding + 8, length);
    if(recv != length)
    {
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(&ctx, encoding, buffer_block_size);
    
    /* Decode the response message and retrieve the operation result status. */
    ResponseMessage resp_m = {0};
    int decode_result = kmip_decode_response_message(&ctx, &resp_m);
    if(decode_result != KMIP_OK)
    {
        kmip_free_response_message(&ctx, &resp_m);
        kmip_free_buffer(&ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_destroy(&ctx);
        return(decode_result);
    }
    
    kmip_free_buffer(&ctx, encoding, buffer_total_size);
    encoding = NULL;

    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        kmip_free_response_message(&ctx, &resp_m);
        kmip_set_buffer(&ctx, NULL, 0);
        kmip_destroy(&ctx);
        return(KMIP_MALFORMED_RESPONSE);
    }
    
    ResponseBatchItem resp_item = resp_m.batch_items[0];
    enum result_status result = resp_item.result_status;
    
    if(result != KMIP_STATUS_SUCCESS)
    {
        kmip_free_response_message(&ctx, &resp_m);
        kmip_set_buffer(&ctx, NULL, 0);
        kmip_destroy(&ctx);
        return(result);
    }
    
    GetResponsePayload *pld = (GetResponsePayload *)resp_item.response_payload;
    
    if(pld->object_type != KMIP_OBJTYPE_SYMMETRIC_KEY)
    {
        kmip_free_response_message(&ctx, &resp_m);
        kmip_set_buffer(&ctx, NULL, 0);
        kmip_destroy(&ctx);
        return(KMIP_OBJECT_MISMATCH);
    }
    
    SymmetricKey *symmetric_key = (SymmetricKey *)pld->object;
    KeyBlock *block = symmetric_key->key_block;
    if((block->key_format_type != KMIP_KEYFORMAT_RAW) || 
       (block->key_wrapping_data != NULL))
    {
        kmip_free_response_message(&ctx, &resp_m);
        kmip_set_buffer(&ctx, NULL, 0);
        kmip_destroy(&ctx);
        return(KMIP_OBJECT_MISMATCH);
    }
    
    KeyValue *block_value = block->key_value;
    ByteString *material = (ByteString *)block_value->key_material;
    
    char *result_key = ctx.calloc_func(ctx.state, 1, material->size);
    *key_size = material->size;
    for(int i = 0; i < *key_size; i++)
    {
        result_key[i] = material->value[i];
    }
    *key = result_key;
    
    /* Clean up the response message, the encoding buffer, and the KMIP */
    /* context. */
    kmip_free_response_message(&ctx, &resp_m);
    kmip_free_buffer(&ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(&ctx, NULL, 0);
    kmip_destroy(&ctx);
    
    return(result);
}

LastResult last_result = {0};

void kmip_clear_last_result(void)
{
    last_result.operation     = 0;
    last_result.result_status = KMIP_STATUS_SUCCESS;
    last_result.result_reason = 0;
    last_result.result_message[0] = 0;
}

int kmip_set_last_result(ResponseBatchItem* value)
{
    if (value)
    {
        last_result.operation = value->operation;
        last_result.result_status = value->result_status;
        last_result.result_reason = value->result_reason;
        if (value->result_message)
            kmip_copy_textstring(last_result.result_message, value->result_message, sizeof(last_result.result_message));
        else
            last_result.result_message[0] = 0;
    }
    return 0;
}

const LastResult* kmip_get_last_result(void)
{
    return &last_result;
}

int kmip_last_reason(void)
{
    return last_result.result_reason;
}

const char* kmip_last_message(void)
{
    return last_result.result_message;
}

int kmip_bio_create_symmetric_key_with_context(KMIP *ctx, BIO *bio,
                                               TemplateAttribute *template_attribute,
                                               char **id, int *id_size)
{
    if(ctx == NULL || bio == NULL || template_attribute == NULL || id == NULL || id_size == NULL)
    {
        return(KMIP_ARG_INVALID);
    }
    
    /* Set up the initial encoding buffer. */
    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;
    
    uint8 *encoding = ctx->calloc_func(ctx->state, buffer_blocks, buffer_block_size);
    if(encoding == NULL)
        return(KMIP_MEMORY_ALLOC_FAILED);
    kmip_set_buffer(ctx, encoding, buffer_total_size);
    
    /* Build the request message. */
    ProtocolVersion pv = {0};
    kmip_init_protocol_version(&pv, ctx->version);
    
    RequestHeader rh = {0};
    kmip_init_request_header(&rh);
    
    rh.protocol_version = &pv;
    rh.maximum_response_size = ctx->max_message_size;
    rh.time_stamp = time(NULL);
    rh.batch_count = 1;
    
    CreateRequestPayload crp = {0};
    crp.object_type = KMIP_OBJTYPE_SYMMETRIC_KEY;
    crp.template_attribute = template_attribute;

    RequestBatchItem rbi = {0};
    kmip_init_request_batch_item(&rbi);
    rbi.operation = KMIP_OP_CREATE;
    rbi.request_payload = &crp;
    
    RequestMessage rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;
    
    /* Add the context credential to the request message if it exists. */
    /* TODO (ph) Update this to add multiple credentials. */
    Authentication auth = {0};
    if(ctx->credential_list != NULL)
    {
        LinkedListItem *item = ctx->credential_list->head;
        if(item != NULL)
        {
            auth.credential = (Credential *)item->data;
            rh.authentication = &auth;
        }
    }
    
    /* Encode the request message. Dynamically resize the encoding buffer */
    /* if it's not big enough. Once encoding succeeds, send the request   */
    /* message.                                                           */
    int encode_result = kmip_encode_request_message(ctx, &rm);
    while(encode_result == KMIP_ERROR_BUFFER_FULL)
    {
        kmip_reset(ctx);
        ctx->free_func(ctx->state, encoding);
        
        buffer_blocks += 1;
        buffer_total_size = buffer_blocks * buffer_block_size;
        
        encoding = ctx->calloc_func(ctx->state, buffer_blocks, buffer_block_size);
        if(encoding == NULL)
        {
            kmip_set_buffer(ctx, NULL, 0);
            return(KMIP_MEMORY_ALLOC_FAILED);
        }
        
        kmip_set_buffer(
            ctx,
            encoding,
            buffer_total_size);
        encode_result = kmip_encode_request_message(ctx, &rm);
    }
    
    if(encode_result != KMIP_OK)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(encode_result);
    }
    
    int sent = BIO_write(bio, ctx->buffer, ctx->index - ctx->buffer);
    if(sent != ctx->index - ctx->buffer)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(ctx, NULL, 0);
    
    /* Read the response message. Dynamically resize the encoding buffer  */
    /* to align with the message size advertised by the message encoding. */
    /* Reject the message if the message size is too large.               */
    buffer_blocks = 1;
    buffer_block_size = 8;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    encoding = ctx->calloc_func(ctx->state, buffer_blocks, buffer_block_size);
    if(encoding == NULL)
        return(KMIP_MEMORY_ALLOC_FAILED);
    
    int recv = BIO_read(bio, encoding, buffer_total_size);
    if((size_t)recv != buffer_total_size)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(ctx, encoding, buffer_total_size);
    ctx->index += 4;
    int length = 0;
    
    kmip_decode_int32_be(ctx, &length);
    kmip_rewind(ctx);
    if(length > ctx->max_message_size)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_EXCEED_MAX_MESSAGE_SIZE);
    }
    
    kmip_set_buffer(ctx, NULL, 0);
    uint8 *extended = ctx->realloc_func(ctx->state, encoding, buffer_total_size + length);
    if(extended == NULL)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    encoding = extended;
    ctx->memset_func(encoding + buffer_total_size, 0, length);
    
    buffer_block_size += length;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    recv = BIO_read(bio, encoding + 8, length);
    if(recv != length)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(ctx, encoding, buffer_block_size);
    
    /* Decode the response message and retrieve the operation results. */
    ResponseMessage resp_m = {0};
    int decode_result = kmip_decode_response_message(ctx, &resp_m);
    
    kmip_set_buffer(ctx, NULL, 0);
    
    if(decode_result != KMIP_OK)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return(decode_result);
    }

    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return(KMIP_MALFORMED_RESPONSE);
    }
    
    ResponseBatchItem resp_item = resp_m.batch_items[0];
    enum result_status result = resp_item.result_status;

    kmip_set_last_result(&resp_item);

    if(result != KMIP_STATUS_SUCCESS)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(result);
    }
    
    {
        CreateResponsePayload *pld = (CreateResponsePayload *)resp_item.response_payload;
        TextString *unique_identifier = (pld != NULL) ? pld->unique_identifier : NULL;
        if(unique_identifier == NULL || unique_identifier->value == NULL ||
           unique_identifier->size == 0)
        {
            kmip_free_response_message(ctx, &resp_m);
            kmip_free_buffer(ctx, encoding, buffer_total_size);
            encoding = NULL;
            kmip_set_buffer(ctx, NULL, 0);
            return(KMIP_INVALID_FIELD);
        }

        char *result_id = ctx->calloc_func(ctx->state, 1, unique_identifier->size);
        if(result_id == NULL)
        {
            kmip_free_response_message(ctx, &resp_m);
            kmip_free_buffer(ctx, encoding, buffer_total_size);
            encoding = NULL;
            kmip_set_buffer(ctx, NULL, 0);
            return(KMIP_MEMORY_ALLOC_FAILED);
        }
        *id_size = unique_identifier->size;
        for(int i = 0; i < *id_size; i++)
        {
            result_id[i] = unique_identifier->value[i];
        }
        *id = result_id;
    }
    
    /* Clean up the response message and the encoding buffer. */
    kmip_free_response_message(ctx, &resp_m);
    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(ctx, NULL, 0);
    
    return(result);
}

int kmip_bio_get_symmetric_key_with_context(KMIP *ctx, BIO *bio,
                                            char *uuid, int uuid_size,
                                            char **key, int *key_size)
{
    if(ctx == NULL || bio == NULL || uuid == NULL || uuid_size <= 0 || key == NULL || key_size == NULL)
    {
        return(KMIP_ARG_INVALID);
    }
    
    /* Set up the initial encoding buffer. */
    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;
    
    uint8 *encoding = ctx->calloc_func(
        ctx->state,
        buffer_blocks,
        buffer_block_size);
    if(encoding == NULL)
    {
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    kmip_set_buffer(ctx, encoding, buffer_total_size);
    
    /* Build the request message. */
    ProtocolVersion pv = {0};
    kmip_init_protocol_version(&pv, ctx->version);
    
    RequestHeader rh = {0};
    kmip_init_request_header(&rh);
    
    rh.protocol_version = &pv;
    rh.maximum_response_size = ctx->max_message_size;
    rh.time_stamp = time(NULL);
    rh.batch_count = 1;
    
    TextString id = {0};
    id.value = uuid;
    id.size = uuid_size;
    
    GetRequestPayload grp = {0};
    grp.unique_identifier = &id;
    
    RequestBatchItem rbi = {0};
    kmip_init_request_batch_item(&rbi);
    rbi.operation = KMIP_OP_GET;
    rbi.request_payload = &grp;
    
    RequestMessage rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;
    
    /* Add the context credential to the request message if it exists. */
    /* TODO (ph) Update this to add multiple credentials. */
    Authentication auth = {0};
    if(ctx->credential_list != NULL)
    {
        LinkedListItem *item = ctx->credential_list->head;
        if(item != NULL)
        {
            auth.credential = (Credential *)item->data;
            rh.authentication = &auth;
        }
    }
    
    /* Encode the request message. Dynamically resize the encoding buffer */
    /* if it's not big enough. Once encoding succeeds, send the request   */
    /* message.                                                           */
    int encode_result = kmip_encode_request_message(ctx, &rm);
    while(encode_result == KMIP_ERROR_BUFFER_FULL)
    {
        kmip_reset(ctx);
        ctx->free_func(ctx->state, encoding);
        
        buffer_blocks += 1;
        buffer_total_size = buffer_blocks * buffer_block_size;
        
        encoding = ctx->calloc_func(
            ctx->state,
            buffer_blocks,
            buffer_block_size);
        if(encoding == NULL)
        {
            return(KMIP_MEMORY_ALLOC_FAILED);
        }
        
        kmip_set_buffer(
            ctx,
            encoding,
            buffer_total_size);
        encode_result = kmip_encode_request_message(ctx, &rm);
    }
    
    if(encode_result != KMIP_OK)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return(encode_result);
    }
    
    int sent = BIO_write(bio, ctx->buffer, ctx->index - ctx->buffer);
    if(sent != ctx->index - ctx->buffer)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return(KMIP_IO_FAILURE);
    }
    
    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;
    
    /* Read the response message. Dynamically resize the encoding buffer  */
    /* to align with the message size advertised by the message encoding. */
    /* Reject the message if the message size is too large.               */
    buffer_blocks = 1;
    buffer_block_size = 8;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    encoding = ctx->calloc_func(ctx->state, buffer_blocks, buffer_block_size);
    if(encoding == NULL)
    {
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    
    int recv = BIO_read(bio, encoding, buffer_total_size);
    if((size_t)recv != buffer_total_size)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(ctx, encoding, buffer_total_size);
    ctx->index += 4;
    int length = 0;
    
    kmip_decode_int32_be(ctx, &length);
    kmip_rewind(ctx);
    if(length > ctx->max_message_size)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return(KMIP_EXCEED_MAX_MESSAGE_SIZE);
    }
    
    kmip_set_buffer(ctx, NULL, 0);
    uint8 *extended = ctx->realloc_func(
        ctx->state,
        encoding,
        buffer_total_size + length);
    if(encoding != extended)
    {
        encoding = extended;
    }
    ctx->memset_func(encoding + buffer_total_size, 0, length);
    
    buffer_block_size += length;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    recv = BIO_read(bio, encoding + 8, length);
    if(recv != length)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(ctx, encoding, buffer_block_size);
    
    /* Decode the response message and retrieve the operation result status. */
    ResponseMessage resp_m = {0};
    int decode_result = kmip_decode_response_message(ctx, &resp_m);
    if(decode_result != KMIP_OK)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return(decode_result);
    }
    
    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;

    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_MALFORMED_RESPONSE);
    }
    
    ResponseBatchItem resp_item = resp_m.batch_items[0];
    enum result_status result = resp_item.result_status;
    
    kmip_set_last_result(&resp_item);
    
    if(result != KMIP_STATUS_SUCCESS)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_set_buffer(ctx, NULL, 0);
        return(result);
    }
    
    GetResponsePayload *pld = (GetResponsePayload *)resp_item.response_payload;
    
    if(pld->object_type != KMIP_OBJTYPE_SYMMETRIC_KEY)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_OBJECT_MISMATCH);
    }
    
    SymmetricKey *symmetric_key = (SymmetricKey *)pld->object;
    KeyBlock *block = symmetric_key->key_block;
    if((block->key_format_type != KMIP_KEYFORMAT_RAW) || 
       (block->key_wrapping_data != NULL))
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_OBJECT_MISMATCH);
    }
    
    KeyValue *block_value = block->key_value;
    ByteString *material = (ByteString *)block_value->key_material;
    
    char *result_key = ctx->calloc_func(ctx->state, 1, material->size);
    *key_size = material->size;
    for(int i = 0; i < *key_size; i++)
    {
        result_key[i] = material->value[i];
    }
    *key = result_key;
    
    /* Clean up the response message, the encoding buffer, and the KMIP */
    /* context. */
    kmip_free_response_message(ctx, &resp_m);
    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(ctx, NULL, 0);
    
    return(result);
}

int kmip_bio_destroy_symmetric_key_with_context(KMIP *ctx, BIO *bio,
                                                char *uuid, int uuid_size)
{
    if(ctx == NULL || bio == NULL || uuid == NULL || uuid_size <= 0)
    {
        return(KMIP_ARG_INVALID);
    }
    
    /* Set up the initial encoding buffer. */
    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;
    
    uint8 *encoding = ctx->calloc_func(ctx->state, buffer_blocks,
                                       buffer_block_size);
    if(encoding == NULL)
    {
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    kmip_set_buffer(ctx, encoding, buffer_total_size);
    
    /* Build the request message. */
    ProtocolVersion pv = {0};
    kmip_init_protocol_version(&pv, ctx->version);
    
    RequestHeader rh = {0};
    kmip_init_request_header(&rh);
    
    rh.protocol_version = &pv;
    rh.maximum_response_size = ctx->max_message_size;
    rh.time_stamp = time(NULL);
    rh.batch_count = 1;
    
    TextString id = {0};
    id.value = uuid;
    id.size = uuid_size;
    
    DestroyRequestPayload drp = {0};
    drp.unique_identifier = &id;
    
    RequestBatchItem rbi = {0};
    kmip_init_request_batch_item(&rbi);
    rbi.operation = KMIP_OP_DESTROY;
    rbi.request_payload = &drp;
    
    RequestMessage rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;
    
    /* Add the context credential to the request message if it exists. */
    /* TODO (ph) Update this to add multiple credentials. */
    Authentication auth = {0};
    if(ctx->credential_list != NULL)
    {
        LinkedListItem *item = ctx->credential_list->head;
        if(item != NULL)
        {
            auth.credential = (Credential *)item->data;
            rh.authentication = &auth;
        }
    }
    
    /* Encode the request message. Dynamically resize the encoding buffer */
    /* if it's not big enough. Once encoding succeeds, send the request   */
    /* message.                                                           */
    int encode_result = kmip_encode_request_message(ctx, &rm);
    while(encode_result == KMIP_ERROR_BUFFER_FULL)
    {
        kmip_reset(ctx);
        ctx->free_func(ctx->state, encoding);
        
        buffer_blocks += 1;
        buffer_total_size = buffer_blocks * buffer_block_size;
        
        encoding = ctx->calloc_func(ctx->state, buffer_blocks,
                                    buffer_block_size);
        if(encoding == NULL)
        {
            kmip_set_buffer(ctx, NULL, 0);
            return(KMIP_MEMORY_ALLOC_FAILED);
        }
        
        kmip_set_buffer(
            ctx,
            encoding,
            buffer_total_size);
        encode_result = kmip_encode_request_message(ctx, &rm);
    }
    
    if(encode_result != KMIP_OK)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(encode_result);
    }
    
    int sent = BIO_write(bio, ctx->buffer, ctx->index - ctx->buffer);
    if(sent != ctx->index - ctx->buffer)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(ctx, NULL, 0);
    
    /* Read the response message. Dynamically resize the encoding buffer  */
    /* to align with the message size advertised by the message encoding. */
    /* Reject the message if the message size is too large.               */
    buffer_blocks = 1;
    buffer_block_size = 8;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    encoding = ctx->calloc_func(ctx->state, buffer_blocks, buffer_block_size);
    if(encoding == NULL)
    {
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    
    int recv = BIO_read(bio, encoding, buffer_total_size);
    if((size_t)recv != buffer_total_size)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(ctx, encoding, buffer_total_size);
    ctx->index += 4;
    int length = 0;
    
    kmip_decode_int32_be(ctx, &length);
    kmip_rewind(ctx);
    if(length > ctx->max_message_size)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_EXCEED_MAX_MESSAGE_SIZE);
    }
    
    kmip_set_buffer(ctx, NULL, 0);
    uint8 *extended = ctx->realloc_func(ctx->state, encoding,
                                        buffer_total_size + length);
    if(encoding != extended)
    {
        encoding = extended;
    }
    ctx->memset_func(encoding + buffer_total_size, 0, length);
    
    buffer_block_size += length;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    recv = BIO_read(bio, encoding + 8, length);
    if(recv != length)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(ctx, encoding, buffer_block_size);
    
    /* Decode the response message and retrieve the operation result status. */
    ResponseMessage resp_m = {0};
    int decode_result = kmip_decode_response_message(ctx, &resp_m);
    
    kmip_set_buffer(ctx, NULL, 0);
    
    if(decode_result != KMIP_OK)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return(decode_result);
    }

    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return(KMIP_MALFORMED_RESPONSE);
    }
    
    ResponseBatchItem resp_item = resp_m.batch_items[0];
    enum result_status result = resp_item.result_status;
    
    /* Clean up the response message and the encoding buffer. */
    kmip_free_response_message(ctx, &resp_m);
    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(ctx, NULL, 0);
    
    return(result);
}

int kmip_bio_send_request_encoding(KMIP *ctx, BIO *bio,
                                   char *request, int request_size,
                                   char **response, int *response_size)
{
    if(ctx == NULL || bio == NULL || request == NULL || request_size <= 0 || response == NULL || response_size == NULL)
    {
        return(KMIP_ARG_INVALID);
    }
    
    /* Send the request message. */
    int sent = BIO_write(bio, request, request_size);
    if(sent != request_size)
    {
        return(KMIP_IO_FAILURE);
    }
    
    /* Read the response message. Dynamically resize the receiving buffer */
    /* to align with the message size advertised by the message encoding. */
    /* Reject the message if the message size is too large.               */
    size_t buffer_blocks = 1;
    size_t buffer_block_size = 8;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;
    
    uint8 *encoding = ctx->calloc_func(ctx->state, buffer_blocks,
                                       buffer_block_size);
    if(encoding == NULL)
    {
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    
    int recv = BIO_read(bio, encoding, buffer_total_size);
    if((size_t)recv != buffer_total_size)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        return(KMIP_IO_FAILURE);
    }
    
    kmip_set_buffer(ctx, encoding, buffer_total_size);
    ctx->index += 4;
    int length = 0;
    
    kmip_decode_int32_be(ctx, &length);
    kmip_rewind(ctx);
    if(length > ctx->max_message_size)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_EXCEED_MAX_MESSAGE_SIZE);
    }
    
    kmip_set_buffer(ctx, NULL, 0);
    uint8 *extended = ctx->realloc_func(ctx->state, encoding,
                                        buffer_total_size + length);
    if(extended == NULL)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    encoding = extended;
    ctx->memset_func(encoding + buffer_total_size, 0, length);
    
    buffer_block_size += length;
    buffer_total_size = buffer_blocks * buffer_block_size;
    
    recv = BIO_read(bio, encoding + 8, length);
    if(recv != length)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_IO_FAILURE);
    }
    
    *response_size = buffer_total_size;
    *response = (char *)encoding;
    
    kmip_set_buffer(ctx, NULL, 0);
    
    return(KMIP_OK);
}

int kmip_bio_query_with_context(KMIP *ctx, BIO *bio, enum query_function queries[], size_t query_count, QueryResponse* query_result)
{
    if (ctx == NULL || bio == NULL || queries == NULL || query_count == 0 || query_result == NULL)
    {
        return(KMIP_ARG_INVALID);
    }

    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;

    uint8 *encoding = ctx->calloc_func(ctx->state, buffer_blocks, buffer_block_size);
    if(encoding == NULL)
    {
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    kmip_set_buffer(ctx, encoding, buffer_total_size);

    /* Build the request message. */


    ProtocolVersion pv = {0};
    kmip_init_protocol_version(&pv, ctx->version);

    RequestHeader rh = {0};
    kmip_init_request_header(&rh);

    rh.protocol_version = &pv;
    rh.maximum_response_size = ctx->max_message_size;
    rh.time_stamp = time(NULL);
    rh.batch_count = 1;

    LinkedList *funclist = ctx->calloc_func(ctx->state, 1, sizeof(LinkedList));
    for(size_t i = 0; i < query_count; i++)
    {
        LinkedListItem *item = ctx->calloc_func(ctx->state, 1, sizeof(LinkedListItem));
        item->data = &queries[i];
        kmip_linked_list_enqueue(funclist, item);
    }
    Functions functions = {0};
    functions.function_list = funclist;

    QueryRequestPayload qrp = {0};
    qrp.functions = &functions;

    RequestBatchItem rbi = {0};
    kmip_init_request_batch_item(&rbi);
    rbi.operation = KMIP_OP_QUERY;
    rbi.request_payload = &qrp;

    RequestMessage rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;

    /* Encode the request message. Dynamically resize the encoding buffer */
    /* if it's not big enough. Once encoding succeeds, send the request   */
    /* message.                                                           */
    int encode_result = kmip_encode_request_message(ctx, &rm);
    while(encode_result == KMIP_ERROR_BUFFER_FULL)
    {
        kmip_reset(ctx);
        ctx->free_func(ctx->state, encoding);

        buffer_blocks += 1;
        buffer_total_size = buffer_blocks * buffer_block_size;

        encoding = ctx->calloc_func(ctx->state, buffer_blocks, buffer_block_size);
        if(encoding == NULL)
        {
            return(KMIP_MEMORY_ALLOC_FAILED);
        }
        kmip_set_buffer(ctx, encoding, buffer_total_size);
        encode_result = kmip_encode_request_message(ctx, &rm);
    }

    if(encode_result != KMIP_OK)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(encode_result);
    }

    char *response = NULL;
    int response_size = 0;

    int result = kmip_bio_send_request_encoding(ctx, bio, (char *)encoding, ctx->index - ctx->buffer, &response, &response_size);
    if(result < 0)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        kmip_free_buffer(ctx, response, response_size);
        encoding = NULL;
        response = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(result);
    }

    kmip_free_query_request_payload(ctx, &qrp);

    if (response)
    {
        FILE* out = fopen( "/tmp/kmip_query.dat", "w" );
        if (out)
        {
            fwrite( response, response_size, 1, out );
            fclose(out);
        }
        // kmip_print_buffer(response, response_size);
    }

    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(ctx, response, response_size);

    /* Decode the response message and retrieve the operation results. */
    ResponseMessage resp_m = {0};
    int decode_result = kmip_decode_response_message(ctx, &resp_m);
    if(decode_result != KMIP_OK)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, response, response_size);
        response = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(decode_result);
    }

    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, response, response_size);
        response = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_MALFORMED_RESPONSE);
    }

    ResponseBatchItem resp_item = resp_m.batch_items[0];
    enum result_status result_status = resp_item.result_status;

    kmip_set_last_result(&resp_item);

    if(result == KMIP_STATUS_SUCCESS)
    {
        kmip_copy_query_result(query_result, (QueryResponsePayload*) resp_item.response_payload);
    }

    /* Clean up the response message, the response buffer, and the KMIP */
    /* context.                                                         */
    kmip_free_response_message(ctx, &resp_m);
    kmip_free_buffer(ctx, response, response_size);
    response = NULL;

    return(result_status);
}

/*
 * Mid-Level API Implementation
 */

int kmip_bio_activate_with_context(KMIP *ctx, BIO *bio, char* key_uuid)
{
    if(ctx == NULL || bio == NULL)
    {
        return(KMIP_ARG_INVALID);
    }
// reject NULL UUID even if pykimp allows it
    if(key_uuid == NULL)
    {
        return(KMIP_INVALID_FIELD);
    }

    // Reset context for new operation
    kmip_reset(ctx);

    /* Set up the initial encoding buffer. */
    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;

    uint8 *buffer = ctx->calloc_func(ctx->state, buffer_blocks, buffer_block_size);
    if(buffer == NULL)
    {
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    kmip_set_buffer(ctx, buffer, buffer_total_size);

    /* Step 1: Build RequestMessage structure */
    ProtocolVersion protocol_version = {0};
    kmip_init_protocol_version(&protocol_version, ctx->version);

    RequestHeader request_header = {0};
    kmip_init_request_header(&request_header);
    request_header.protocol_version = &protocol_version;
    request_header.maximum_response_size = ctx->max_message_size;
    request_header.time_stamp = time(NULL);
    request_header.batch_count = 1;

    /* Build Activate Request Payload */
    TextString unique_id = {0};

    ActivateRequestPayload activate_payload = {0};
    activate_payload.unique_identifier = NULL;

    // Set unique identifier
    if(key_uuid != NULL)
    {
        unique_id.value = key_uuid;
        unique_id.size = kmip_strnlen_s(key_uuid, 36);
        activate_payload.unique_identifier = &unique_id;
    }

    /* Build Batch Item */
    RequestBatchItem batch_item = {0};
    kmip_init_request_batch_item(&batch_item);
    batch_item.operation = KMIP_OP_ACTIVATE;
    batch_item.request_payload = &activate_payload;

    /* Build Request Message */
    RequestMessage request_message = {0};
    request_message.request_header = &request_header;
    request_message.batch_items = &batch_item;
    request_message.batch_count = 1;

    // Add the context credential to the request message if it exists.
    // TODO (ph) Update this to add multiple credentials.
    Authentication auth = {0};
    if(ctx->credential_list != NULL)
    {
        LinkedListItem *item = ctx->credential_list->head;
        if(item != NULL)
        {
            auth.credential = (Credential *)item->data;
            request_header.authentication = &auth;
        }
    }

    /* Step 2: Encode request */
    int encode_result = kmip_encode_request_message(ctx, &request_message);

    if(encode_result != KMIP_OK)
    {
        kmip_free_buffer(ctx, buffer, buffer_total_size);
        buffer = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(encode_result);
    }

    /* Step 3: Send request and receive response */
    char *response_buffer = NULL;
    int response_size = 0;

    int result = kmip_bio_send_request_encoding(ctx, bio, (char *)buffer, ctx->index - ctx->buffer, &response_buffer, &response_size);
    if(result < 0)
    {
        kmip_free_buffer(ctx, buffer, buffer_total_size);
        kmip_free_buffer(ctx, response_buffer, response_size);
        buffer = NULL;
        response_buffer = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(result);
    }

    kmip_free_buffer(ctx, buffer, buffer_total_size);
    buffer = NULL;
    kmip_set_buffer(ctx, response_buffer, response_size);

    // Decode the response message and retrieve the operation results.
    ResponseMessage response_message = {0};
    int decode_result = kmip_decode_response_message(ctx, &response_message);
    if(decode_result != KMIP_OK)
    {
        kmip_push_error_frame(ctx, __func__, __LINE__);
        kmip_free_response_message(ctx, &response_message);
        kmip_free_buffer(ctx, response_buffer, response_size);
        response_buffer = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(decode_result);
    }

    if(response_message.batch_count != 1 || response_message.batch_items == NULL)
    {
        kmip_push_error_frame(ctx, __func__, __LINE__);
        kmip_free_response_message(ctx, &response_message);
        kmip_free_buffer(ctx, response_buffer, response_size);
        response_buffer = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_MALFORMED_RESPONSE);
    }

    ResponseBatchItem response_item = response_message.batch_items[0];
    enum result_status resultstatus = response_item.result_status;

    kmip_set_last_result(&response_item);

    ActivateResponsePayload *activate_response = (ActivateResponsePayload *)response_item.response_payload;
    if(activate_response == NULL || activate_response->unique_identifier == NULL)
    {
        kmip_push_error_frame(ctx, __func__, __LINE__);
        ctx->free_func(ctx->state, response_buffer);
        kmip_free_response_message(ctx, &response_message);
        return(KMIP_INVALID_FIELD);
    }

    // Clean up the response message, the response buffer, and the KMIP  context.
    kmip_free_response_message(ctx, &response_message);
    kmip_free_buffer(ctx, response_buffer, response_size);
    response_buffer = NULL;

    return(resultstatus);
}

int
kmip_bio_encrypt_with_context(
    KMIP *ctx,
    BIO *bio,
    char *key_uuid,
    int key_uuid_size,
    uint8 *plaintext,
    int plaintext_size,
    uint8 *additional_data,
    int additional_data_size,
    CryptographicParameters *params,
    uint8 **ciphertext,
    int *ciphertext_size,
    uint8 **iv,
    int *iv_size,
    uint8 **tag,
    int *tag_size)
{
    if(ctx == NULL || bio == NULL || plaintext == NULL || plaintext_size < 0 || ciphertext == NULL || ciphertext_size == NULL)
    {
        return(KMIP_ARG_INVALID);
    }

    // Reset context for new operation
    kmip_reset(ctx);

    /* Set up the initial encoding buffer. */
    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;

    uint8 *encoding = ctx->calloc_func(ctx->state, buffer_blocks, buffer_block_size);
    if(encoding == NULL)
    {
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    kmip_set_buffer(ctx, encoding, buffer_total_size);

    /* Step 1: Build RequestMessage structure */
    ProtocolVersion protocol_version = {0};
    kmip_init_protocol_version(&protocol_version, ctx->version);

    RequestHeader request_header = {0};
    kmip_init_request_header(&request_header);
    request_header.protocol_version = &protocol_version;
    request_header.maximum_response_size = ctx->max_message_size;
    request_header.time_stamp = time(NULL);
    request_header.batch_count = 1;

    /* Build Encrypt Request Payload */
    TextString unique_id = {0};

    ByteString data = {0};
    data.value = plaintext;
    data.size = plaintext_size;

    ByteString auth_enc_additional_data = {0};
    auth_enc_additional_data.value = additional_data;
    auth_enc_additional_data.size = additional_data_size;

    EncryptRequestPayload encrypt_payload = {0};
    encrypt_payload.unique_identifier = NULL;
    encrypt_payload.cryptographic_parameters = NULL;
    encrypt_payload.data = &data;
    encrypt_payload.iv_counter_nonce = NULL;
    encrypt_payload.correlation_value = NULL; /* TODO how to implement this? */
    encrypt_payload.init_indicator = KMIP_UNSET; /* TODO how to implement this? */
    encrypt_payload.final_indicator = KMIP_UNSET; /* TODO how to implement this? */
    encrypt_payload.authenticated_encryption_additional_data =
        (additional_data != NULL) ? &auth_enc_additional_data : NULL;

    // Set crypto parameters
    if(params != NULL)
    {
        encrypt_payload.cryptographic_parameters = params;
    }
    // Set unique identifier
    if(key_uuid != NULL)
    {
        unique_id.value = key_uuid;
        unique_id.size = key_uuid_size;
        encrypt_payload.unique_identifier = &unique_id;
    }
    // Set IV

    /* Build Batch Item */
    RequestBatchItem batch_item = {0};
    kmip_init_request_batch_item(&batch_item);
    batch_item.operation = KMIP_OP_ENCRYPT;
    batch_item.request_payload = &encrypt_payload;

    /* Build Request Message */
    RequestMessage request_message = {0};
    request_message.request_header = &request_header;
    request_message.batch_items = &batch_item;
    request_message.batch_count = 1;


    // Add the context credential to the request message if it exists.
    // TODO (ph) Update this to add multiple credentials.
    Authentication auth = {0};
    if(ctx->credential_list != NULL)
    {
        LinkedListItem *item = ctx->credential_list->head;
        if(item != NULL)
        {
            auth.credential = (Credential *)item->data;
            request_header.authentication = &auth;
        }
    }

    /* Step 2: Encode request */

    /* Encode the request message. Dynamically resize the encoding buffer */
    /* if it's not big enough. Once encoding succeeds, send the request   */
    /* message.                                                           */
    int encode_result = kmip_encode_request_message(ctx, &request_message);

    if(encode_result != KMIP_OK)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(encode_result);
    }

    /* Step 3: Send request and receive response */

    char *response_buffer = NULL;
    int response_size = 0;

    int send_result = kmip_bio_send_request_encoding(ctx, bio, (char *)encoding, ctx->index - ctx->buffer, &response_buffer, &response_size);

    if(send_result < 0)
    {
        kmip_push_error_frame(ctx, __func__, __LINE__);
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        kmip_free_buffer(ctx, response_buffer, response_size);
        encoding = NULL;
        response_buffer = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(send_result);
    }

    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;

    // Step 4: Decode the response message and retrieve the operation results.
    kmip_set_buffer(ctx, response_buffer, response_size);
    ResponseMessage response_message = {0};
    int decode_result = kmip_decode_response_message(ctx, &response_message);
    if(decode_result != KMIP_OK)
    {
        kmip_push_error_frame(ctx, __func__, __LINE__);
        kmip_free_response_message(ctx, &response_message);
        kmip_free_buffer(ctx, response_buffer, response_size);
        response_buffer = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(decode_result);
    }

    if(response_message.batch_count != 1 || response_message.batch_items == NULL)
    {
        kmip_push_error_frame(ctx, __func__, __LINE__);
        kmip_free_response_message(ctx, &response_message);
        kmip_free_buffer(ctx, response_buffer, response_size);
        response_buffer = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_MALFORMED_RESPONSE);
    }

    /* Step 5: Check operation status */
    ResponseBatchItem response_item = response_message.batch_items[0];
    enum result_status resultstatus = response_item.result_status;

    kmip_set_last_result(&response_item);

    if(resultstatus != KMIP_STATUS_SUCCESS)
    {
        kmip_push_error_frame(ctx, __func__, __LINE__);
        kmip_free_response_message(ctx, &response_message);
        kmip_free_buffer(ctx, response_buffer, response_size);
        response_buffer = NULL;
        kmip_set_buffer(ctx, NULL, 0);

        return(resultstatus);
    }

    EncryptResponsePayload *encrypt_response = (EncryptResponsePayload *)response_item.response_payload;
    if(encrypt_response == NULL || encrypt_response->data == NULL)
    {
        kmip_push_error_frame(ctx, __func__, __LINE__);
        kmip_free_response_message(ctx, &response_message);
        kmip_free_buffer(ctx, response_buffer, response_size);
        response_buffer = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_INVALID_FIELD);
    }

    if(resultstatus == KMIP_STATUS_SUCCESS)
    {
        if(encrypt_response->data != NULL && encrypt_response->data->value != NULL && encrypt_response->data->size > 0)
        {
            // Copy ciphertext to output
            *ciphertext_size = encrypt_response->data->size;
            *ciphertext = ctx->calloc_func(ctx->state, 1, *ciphertext_size);

            if(*ciphertext == NULL)
            {
                kmip_push_error_frame(ctx, __func__, __LINE__);
                ctx->free_func(ctx->state, response_buffer);
                kmip_free_response_message(ctx, &response_message);
                return(KMIP_MEMORY_ALLOC_FAILED);
            }
            kmip_memcpy(ctx, *ciphertext, encrypt_response->data->value, *ciphertext_size);
        }

        // Copy IV_COUNTER_NONCE
        if(encrypt_response->iv_counter_nonce != NULL && encrypt_response->iv_counter_nonce->value != NULL && encrypt_response->iv_counter_nonce->size > 0)
        {
            // Copy IV_COUNTER_NONCE to output
            *iv_size = encrypt_response->iv_counter_nonce->size;
            *iv = ctx->calloc_func(ctx->state, 1, *iv_size);

            if(*iv == NULL)
            {
                kmip_push_error_frame(ctx, __func__, __LINE__);
                ctx->free_func(ctx->state, response_buffer);
                kmip_free_response_message(ctx, &response_message);
                return(KMIP_MEMORY_ALLOC_FAILED);
            }
            kmip_memcpy(ctx, *iv, encrypt_response->iv_counter_nonce->value, *iv_size);

        }
        if(encrypt_response->authenticated_encryption_tag != NULL && encrypt_response->authenticated_encryption_tag->value != NULL && encrypt_response->authenticated_encryption_tag->size > 0) {
          if (tag != NULL) {
            *tag_size = encrypt_response->authenticated_encryption_tag->size;
            *tag = ctx->calloc_func(ctx->state, 1, *tag_size);
            if (*tag == NULL)
            {
                kmip_push_error_frame(ctx, __func__, __LINE__);
                ctx->free_func(ctx->state, response_buffer);
                kmip_free_response_message(ctx, &response_message);
                return(KMIP_MEMORY_ALLOC_FAILED);
            }
            kmip_memcpy(ctx, *tag, encrypt_response->authenticated_encryption_tag->value, *tag_size);
          }
        }
    }

    // Clean up the response message, the response buffer, and the KMIP  context.
    kmip_free_response_message(ctx, &response_message);
    kmip_free_buffer(ctx, response_buffer, response_size);
    response_buffer = NULL;
    kmip_set_buffer(ctx, NULL, 0);

    return(KMIP_OK);
}

/* Ensure this is in src/kmip_bio.c */
int kmip_bio_revoke_with_context(KMIP *ctx, BIO *bio, char *key_uuid, int key_uuid_size, int reason)
{
    if(ctx == NULL || bio == NULL || key_uuid == NULL) return(KMIP_ARG_INVALID);

    kmip_reset(ctx);
    size_t buffer_total_size = 2048;
    uint8 *encoding = ctx->calloc_func(ctx->state, 1, buffer_total_size);
    if(encoding == NULL) return(KMIP_MEMORY_ALLOC_FAILED);
    kmip_set_buffer(ctx, encoding, buffer_total_size);

    ProtocolVersion pv = {0};
    kmip_init_protocol_version(&pv, ctx->version);

    RequestHeader rh = {0};
    kmip_init_request_header(&rh);
    rh.protocol_version = &pv;
    rh.time_stamp = time(NULL);
    rh.batch_count = 1;

    RevocationReason rr = {0};
    rr.revocation_reason_code = reason;

    RevokeRequestPayload rrp = {0};
    TextString ts_id = {0};
    ts_id.value = key_uuid;
    ts_id.size = key_uuid_size;
    rrp.unique_identifier = &ts_id;
    rrp.revocation_reason = &rr;

    RequestBatchItem rbi = {0};
    kmip_init_request_batch_item(&rbi);
    rbi.operation = KMIP_OP_REVOKE;
    rbi.request_payload = &rrp;

    RequestMessage rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;

    int encode_result = kmip_encode_request_message(ctx, &rm);
    if(encode_result != KMIP_OK) {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        return encode_result;
    }

    char *response_buffer = NULL;
    int response_size = 0;
    int result = kmip_bio_send_request_encoding(ctx, bio, (char*)ctx->buffer, ctx->index - ctx->buffer, &response_buffer, &response_size);
    
    kmip_free_buffer(ctx, encoding, buffer_total_size);
    if(result < 0) return result;

    kmip_set_buffer(ctx, (uint8*)response_buffer, response_size);
    ResponseMessage resp_m = {0};
    int decode_result = kmip_decode_response_message(ctx, &resp_m);
    
    int final_status = KMIP_STATUS_OPERATION_FAILED;
    if(decode_result == KMIP_OK && resp_m.batch_items != NULL) {
        final_status = resp_m.batch_items[0].result_status;
        kmip_set_last_result(&resp_m.batch_items[0]);
    }

    kmip_free_response_message(ctx, &resp_m);
    kmip_free_buffer(ctx, (uint8*)response_buffer, response_size);
    return final_status;
}

int
kmip_bio_decrypt_with_context(
    KMIP *ctx,
    BIO *bio,
    char *key_uuid,
    int key_uuid_size,
    uint8 *ciphertext,
    int ciphertext_size,
    uint8 *additional_data,
    int additional_data_size,
    uint8 *iv,
    int iv_size,
    uint8 *tag,
    int tag_size,
    CryptographicParameters *params,
    uint8 **plaintext,
    int *plaintext_size)
{
    if(ctx == NULL || bio == NULL || ciphertext == NULL ||
       plaintext == NULL || plaintext_size == NULL)
    {
        return(KMIP_ARG_INVALID);
    }

    /* Reset context for new operation */
    kmip_reset(ctx);

   /* Set up the initial encoding buffer. */
    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;

    uint8 *encoding = ctx->calloc_func(ctx->state, buffer_blocks, buffer_block_size);
    if(encoding == NULL)
    {
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    kmip_set_buffer(ctx, encoding, buffer_total_size);

    /* Step 1: Build RequestMessage structure */
    ProtocolVersion protocol_version = {0};
    kmip_init_protocol_version(&protocol_version, ctx->version);

    RequestHeader request_header = {0};
    kmip_init_request_header(&request_header);
    request_header.protocol_version = &protocol_version;
    request_header.maximum_response_size = ctx->max_message_size;
    request_header.time_stamp = time(NULL);
    request_header.batch_count = 1;

    /* Build Decrypt Request Payload */
    TextString unique_id = {0};

    ByteString data = {0};
    data.value = ciphertext;
    data.size = ciphertext_size;

    ByteString auth_enc_additional_data = {0};
    auth_enc_additional_data.value = additional_data;
    auth_enc_additional_data.size = additional_data_size;

    ByteString auth_tag = {0};
    auth_tag.value = tag;
    auth_tag.size = tag_size;

    ByteString iv_data = {0};

    DecryptRequestPayload decrypt_payload = {0};
    decrypt_payload.unique_identifier = NULL;
    decrypt_payload.cryptographic_parameters = NULL;
    decrypt_payload.data = &data;
    decrypt_payload.iv_counter_nonce = NULL;
    decrypt_payload.correlation_value = NULL; /* TODO how to implement this? */
    decrypt_payload.init_indicator = KMIP_UNSET; /* TODO how to implement this? */
    decrypt_payload.final_indicator = KMIP_UNSET; /* TODO how to implement this? */
    decrypt_payload.authenticated_encryption_additional_data =
        (additional_data != NULL) ? &auth_enc_additional_data : NULL;
    decrypt_payload.authenticated_encryption_tag =
        (tag != NULL) ? &auth_tag : NULL;

    // Set unique identifier
    if(key_uuid != NULL)
    {
        unique_id.value = key_uuid;
        unique_id.size = key_uuid_size;
        decrypt_payload.unique_identifier = &unique_id;
    }

    // Set crypto parameters
    if(params != NULL)
    {
        decrypt_payload.cryptographic_parameters = params;
    }

    // Set IV parameters
    if(iv != NULL && iv_size > 0)
    {
        iv_data.value = iv;
        iv_data.size = iv_size;
        decrypt_payload.iv_counter_nonce = &iv_data;
    }


    /* Build Batch Item */
    RequestBatchItem batch_item = {0};
    kmip_init_request_batch_item(&batch_item);
    batch_item.operation = KMIP_OP_DECRYPT;
    batch_item.request_payload = &decrypt_payload;

    /* Build Request Message */
    RequestMessage request_message = {0};
    request_message.request_header = &request_header;
    request_message.batch_items = &batch_item;
    request_message.batch_count = 1;

    // Add the context credential to the request message if it exists.
    // TODO (ph) Update this to add multiple credentials.
    Authentication auth = {0};
    if(ctx->credential_list != NULL)
    {
        LinkedListItem *item = ctx->credential_list->head;
        if(item != NULL)
        {
            auth.credential = (Credential *)item->data;
            request_header.authentication = &auth;
        }
    }

    /* Step 2: Encode request */
    int encode_result = kmip_encode_request_message(ctx, &request_message);

    if(encode_result != KMIP_OK)
    {
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(encode_result);
    }

    /* Step 3: Send request and receive response */
    char *response_buffer = NULL;
    int response_size = 0;

    int send_result = kmip_bio_send_request_encoding(ctx, bio, (char*)encoding, ctx->index - ctx->buffer, &response_buffer, &response_size);

    if(send_result < 0)
    {
        kmip_push_error_frame(ctx, __func__, __LINE__);
        kmip_free_buffer(ctx, encoding, buffer_total_size);
        kmip_free_buffer(ctx, response_buffer, response_size);
        encoding = NULL;
        response_buffer = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(send_result);
    }

    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;

    // Step 4: Decode the response message and retrieve the operation results.
    kmip_set_buffer(ctx, response_buffer, response_size);
    ResponseMessage response_message = {0};
    int decode_result = kmip_decode_response_message(ctx, &response_message);

    if(decode_result != KMIP_OK)
    {
        kmip_push_error_frame(ctx, __func__, __LINE__);
        kmip_free_response_message(ctx, &response_message);
        kmip_free_buffer(ctx, response_buffer, response_size);
        response_buffer = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(decode_result);
    }

    if(response_message.batch_count != 1 || response_message.batch_items == NULL)
    {
        kmip_push_error_frame(ctx, __func__, __LINE__);
        kmip_free_response_message(ctx, &response_message);
        kmip_free_buffer(ctx, response_buffer, response_size);
        response_buffer = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_MALFORMED_RESPONSE);
    }

    /* Step 5: Check operation status */
    ResponseBatchItem response_item = response_message.batch_items[0];
    enum result_status resultstatus = response_item.result_status;

    kmip_set_last_result(&response_item);

    if(resultstatus != KMIP_STATUS_SUCCESS)
    {
        kmip_push_error_frame(ctx, __func__, __LINE__);
        kmip_free_response_message(ctx, &response_message);
        kmip_free_buffer(ctx, response_buffer, response_size);
        response_buffer = NULL;
        kmip_set_buffer(ctx, NULL, 0);

        return(resultstatus);
    }

    /* Step 6: Extract plaintext from response */
    DecryptResponsePayload *decrypt_response = (DecryptResponsePayload *)response_item.response_payload;

    if(decrypt_response == NULL || decrypt_response->data == NULL)
    {
        kmip_push_error_frame(ctx, __func__, __LINE__);
        kmip_free_response_message(ctx, &response_message);
        kmip_free_buffer(ctx, response_buffer, response_size);
        response_buffer = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_INVALID_FIELD);
    }

    /* Copy plaintext to output */
    *plaintext_size = decrypt_response->data->size;
    *plaintext = ctx->calloc_func(ctx->state, 1, *plaintext_size);

    if(*plaintext == NULL)
    {
        kmip_push_error_frame(ctx, __func__, __LINE__);
        kmip_free_response_message(ctx, &response_message);
        kmip_free_buffer(ctx, response_buffer, response_size);
        response_buffer = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    kmip_memcpy(ctx, *plaintext, decrypt_response->data->value, *plaintext_size);

    /* Step 7: Cleanup */
    kmip_free_response_message(ctx, &response_message);
    kmip_free_buffer(ctx, response_buffer, response_size);
    response_buffer = NULL;
    kmip_set_buffer(ctx, NULL, 0);

    return(KMIP_OK);
}

/*
 * High-Level API Implementation
 */

int
kmip_bio_encrypt(
    BIO *bio,
    char *key_uuid,
    int key_uuid_size,
    uint8 *plaintext,
    int plaintext_size,
    uint8 *additional_data,
    int additional_data_size,
    CryptographicParameters *params,
    uint8 **ciphertext,
    int *ciphertext_size,
    uint8 **iv,
    int *iv_size,
    uint8 **tag,
    int *tag_size)
{
    /* Create and initialize context */
    KMIP ctx = {0};
    kmip_init(&ctx, NULL, 0, KMIP_1_2);

    /* Call mid-level function */
    int result = kmip_bio_encrypt_with_context(
        &ctx,
        bio,
        key_uuid,
        key_uuid_size,
        plaintext,
        plaintext_size,
        additional_data,
        additional_data_size,
        params,
        ciphertext,
        ciphertext_size,
        iv,
        iv_size,
        tag,
        tag_size);

    /* Cleanup context */
    kmip_destroy(&ctx);

    return(result);
}

int
kmip_bio_decrypt(
    BIO *bio,
    char *key_uuid,
    int key_uuid_size,
    uint8 *ciphertext,
    int ciphertext_size,
    uint8 *additional_data,
    int additional_data_size,
    uint8 *iv,
    int iv_size,
    uint8 *tag,
    int tag_size,
    CryptographicParameters *params,
    uint8 **plaintext,
    int *plaintext_size)
{
    /* Create and initialize context */
    KMIP ctx = {0};
    kmip_init(&ctx, NULL, 0, KMIP_1_2);

    /* Call mid-level function */
    int result = kmip_bio_decrypt_with_context(
        &ctx,
        bio,
        key_uuid,
        key_uuid_size,
        ciphertext,
        ciphertext_size,
        additional_data,
        additional_data_size,
        iv,
        iv_size,
        tag,
        tag_size,
        params,
        plaintext,
        plaintext_size);

    /* Cleanup context */
    kmip_destroy(&ctx);

    return(result);
}
