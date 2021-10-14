/**
 * digest.h
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 *
 * Wrapper for OpenSSL EVP_MD*.
 */

#pragma once

// STL libraries.
#include <string>

// OpenSSL libraries.
#include <openssl/evp.h>

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
	std::function<const EVP_MD*()> md_builder;

	inline std::string operator() (const std::string& data) const
	{
		return _hex_digest(this->md_builder(), data);
	}
};

// TESTME: new_digest
// TODO: docs for 'new_digest'
inline Digest new_digest(const std::string& name)
{
	return Digest{[name]() -> const EVP_MD* { return EVP_get_digestbyname(name.c_str()); }};
}

// TESTME: new_digest
// TODO: docs for 'new_digest'
inline Digest new_digest(const EVP_MD* (*md)())
{
	return Digest{[md]() -> const EVP_MD* { return md(); }};
}

__CRYPTO_END__
