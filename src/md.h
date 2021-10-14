/**
 * md.h
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 *
 * MD hash functions wrappers from openssl library.
 */

#pragma once

// OpenSSL libraries.
#include <openssl/evp.h>

// Module definitions.
#include "./_def_.h"

// Crypto libraries.
#include "./digest.h"


__CRYPTO_BEGIN__

static inline Digest md5 = new_digest(EVP_md5);

__CRYPTO_END__
