/**
 * hmac.h
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 *
 * HMAC with SHA implementation using on OpenSSL.
 */

#pragma once

// C++ libraries.
#include <string>

// OpenSSL libraries.
#include <openssl/evp.h>

// Module definitions.
#include "./_def_.h"


__CRYPTO_BEGIN__

class HMAC
{
public:
	[[nodiscard]]
	virtual std::string sign(const std::string& data) const = 0;

	[[nodiscard]]
	virtual bool verify(const std::string& data, const std::string& signature) const = 0;

	[[nodiscard]]
	virtual std::string name() const = 0;
};

class HS : public HMAC
{
public:
	/**
	 * \param secret_key
	 * \param md Pointer to hash function
	 * \param alg_name Algorithm short name
	 */
	inline HS(std::string secret_key, const EVP_MD* (*md)(), std::string alg_name) :
		_secret_key(std::move(secret_key)), _md(md), _alg_name(std::move(alg_name))
	{

	}

	[[nodiscard]]
	std::string sign(const std::string& data) const override;

	[[nodiscard]]
	bool verify(const std::string& data, const std::string& signature) const override;

	[[nodiscard]]
	inline std::string name() const override
	{
		return this->_alg_name;
	}

private:
	const std::string _secret_key;
	const EVP_MD* (*_md)();
	const std::string _alg_name;
};

class HS256 : public HS
{
public:
	explicit HS256(std::string secret_key) :
		HS(std::move(secret_key), EVP_sha256, "HS256")
	{
	}
};

class HS384 : public HS
{
public:
	explicit HS384(std::string secret_key) :
		HS(std::move(secret_key), EVP_sha384, "HS384")
	{
	}
};

class HS512 : public HS
{
public:
	explicit HS512(std::string secret_key) :
		HS(std::move(secret_key), EVP_sha512, "HS512")
	{
	}
};

__CRYPTO_END__
