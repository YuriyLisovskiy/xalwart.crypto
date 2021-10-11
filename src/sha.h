/**
 * sha.h
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 *
 * SHA hash functions wrappers from openssl library.
 */

#pragma once

// STL libraries.
#include <string>

// OpenSSL libraries.
#include <openssl/evp.h>

// Module definitions.
#include "./_def_.h"

// Crypto libraries.
#include "./utilities.h"


__CRYPTO_BEGIN__

inline std::string sha256(const std::string& data)
{
	return hex_digest(EVP_sha256, data);
}

__CRYPTO_END__
