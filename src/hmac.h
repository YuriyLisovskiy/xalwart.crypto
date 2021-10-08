/**
 * hmac.h
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 *
 * SHA256 adaptation from openssl library.
 */

#pragma once

// C++ libraries.
#include <string>

// OpenSSL libraries.
#include <openssl/evp.h>

// Module definitions.
#include "./_def_.h"


__CRYPTO_BEGIN__

// Class for HMAC family of algorithms.
class HmacSHA
{
public:
	/**
	 * \param secret_key
	 * \param md Pointer to hash function
	 * \param alg_name Algorithm short name
	 */
	inline HmacSHA(std::string secret_key, const EVP_MD* (*md)(), std::string alg_name) :
		_secret_key(std::move(secret_key)), _md(md), _alg_name(std::move(alg_name))
	{

	}

	[[nodiscard]]
	std::string sign(const std::string& data) const;

	[[nodiscard]]
	bool verify(const std::string& data, const std::string& signature) const;

	[[nodiscard]]
	inline std::string name() const
	{
		return this->_alg_name;
	}

private:
	const std::string _secret_key;
	const EVP_MD* (*_md)();
	const std::string _alg_name;
};

class HS256 : public HmacSHA
{
public:
	explicit HS256(std::string secret_key) :
		HmacSHA(std::move(secret_key), EVP_sha256, "HS256")
	{
	}
};

class HS384 : public HmacSHA
{
public:
	explicit HS384(std::string secret_key) :
		HmacSHA(std::move(secret_key), EVP_sha384, "HS384")
	{
	}
};

class HS512 : public HmacSHA
{
public:
	explicit HS512(std::string secret_key) :
		HmacSHA(std::move(secret_key), EVP_sha512, "HS512")
	{
	}
};

__CRYPTO_END__
