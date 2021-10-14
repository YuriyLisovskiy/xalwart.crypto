/**
 * sha.h
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 *
 * SHA hash functions wrappers from openssl library.
 */

#pragma once

// OpenSSL libraries.
#include <openssl/evp.h>

// Module definitions.
#include "./_def_.h"

// Crypto libraries.
#include "./digest.h"


__CRYPTO_BEGIN__

static inline Digest sha1 = new_digest(EVP_sha1);
static inline Digest sha224 = new_digest(EVP_sha224);
static inline Digest sha256 = new_digest(EVP_sha256);
static inline Digest sha384 = new_digest(EVP_sha384);
static inline Digest sha512 = new_digest(EVP_sha512);
static inline Digest sha3_224 = new_digest(EVP_sha3_224);
static inline Digest sha3_256 = new_digest(EVP_sha3_256);
static inline Digest sha3_384 = new_digest(EVP_sha3_384);
static inline Digest sha3_512 = new_digest(EVP_sha3_512);

__CRYPTO_END__
