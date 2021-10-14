/**
 * digest.h
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 *
 * Wrapper for OpenSSL EVP_MD*.
 * Definitions of common hash algorithms.
 */

#pragma once

// STL libraries.
#include <string>
#include <functional>

// OpenSSL libraries.
#include <openssl/evp.h>

// Base libraries.
#include <xalwart.base/exceptions.h>

// Module definitions.
#include "./_def_.h"


__CRYPTO_BEGIN__

// TESTME: _hex_digest
// TODO: docs for '_hex_digest'
extern std::string _hex_digest(const EVP_MD* md, const std::string& data);

// TESTME: Digest
// TODO: docs for 'Digest'
struct Digest final
{
	std::function<const EVP_MD*()> evp_md;

	inline std::string operator() (const std::string& data) const
	{
		if (!this->evp_md)
		{
			throw NullPointerException("Digest function is nullptr", _ERROR_DETAILS_);
		}

		return _hex_digest(this->evp_md(), data);
	}
};

// TESTME: new_digest
// TODO: docs for 'new_digest'
extern Digest new_digest(const std::string& name);

// TESTME: new_digest
// TODO: docs for 'new_digest'
inline Digest new_digest(const EVP_MD* (*md)())
{
	if (!md)
	{
		throw NullPointerException("md is nullptr", _ERROR_DETAILS_);
	}

	return Digest{[md]() -> const EVP_MD* { return md(); }};
}

static inline Digest blake2b512 = new_digest(EVP_blake2b512);
static inline Digest blake2s256 = new_digest(EVP_blake2s256);

static inline Digest md5 = new_digest(EVP_md5);

static inline Digest sha1 = new_digest(EVP_sha1);
static inline Digest sha224 = new_digest(EVP_sha224);
static inline Digest sha256 = new_digest(EVP_sha256);
static inline Digest sha384 = new_digest(EVP_sha384);
static inline Digest sha512 = new_digest(EVP_sha512);
static inline Digest sha3_224 = new_digest(EVP_sha3_224);
static inline Digest sha3_256 = new_digest(EVP_sha3_256);
static inline Digest sha3_384 = new_digest(EVP_sha3_384);
static inline Digest sha3_512 = new_digest(EVP_sha3_512);

static inline Digest shake128 = new_digest(EVP_shake128);
static inline Digest shake256 = new_digest(EVP_shake256);

__CRYPTO_END__
