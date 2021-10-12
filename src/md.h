/**
 * md.h
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 *
 * MD hash functions wrappers from openssl library.
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

inline std::string md5(const std::string& data)
{
	return hex_digest(EVP_md5, data);
}

__CRYPTO_END__
