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

inline std::string sha1(const std::string& data)
{
	return hex_digest(EVP_sha1, data);
}

inline std::string sha224(const std::string& data)
{
	return hex_digest(EVP_sha224, data);
}

inline std::string sha256(const std::string& data)
{
	return hex_digest(EVP_sha256, data);
}

inline std::string sha384(const std::string& data)
{
	return hex_digest(EVP_sha384, data);
}

inline std::string sha512(const std::string& data)
{
	return hex_digest(EVP_sha512, data);
}

inline std::string sha3_224(const std::string& data)
{
	return hex_digest(EVP_sha3_224, data);
}

inline std::string sha3_256(const std::string& data)
{
	return hex_digest(EVP_sha3_256, data);
}

inline std::string sha3_384(const std::string& data)
{
	return hex_digest(EVP_sha3_384, data);
}

inline std::string sha3_512(const std::string& data)
{
	return hex_digest(EVP_sha3_512, data);
}

__CRYPTO_END__
