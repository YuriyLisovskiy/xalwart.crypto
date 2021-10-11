/**
 * hmac.h
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 *
 * HMAC with SHA implementation using on OpenSSL.
 */

#pragma once

// STL libraries.
#include <string>

// OpenSSL libraries.
#include <openssl/evp.h>

// Module definitions.
#include "./_def_.h"

// Crypto libraries.
#include "./abc.h"


__CRYPTO_BEGIN__

class HMAC : public abc::ISignatureAlgorithm
{
public:
	/**
	 * \param secret_key
	 * \param md Pointer to hash function
	 * \param alg_name Algorithm short name
	 */
	inline HMAC(std::string secret_key, const EVP_MD* (*md)(), std::string alg_name) :
		_secret_key(std::move(secret_key)), _md(md), _alg_name(std::move(alg_name))
	{
		this->_original_secret_key = this->_secret_key;
	}

	[[nodiscard]]
	std::string sign(const std::string& data) const override;

	[[nodiscard]]
	std::string sign_to_hex(const std::string& data) const override;

	[[nodiscard]]
	bool verify(const std::string& data, const std::string& signature) const override;

	inline void update_secret_key(const std::string& new_key) override
	{
		this->_secret_key = new_key;
	}

	inline void reset_secret_key() override
	{
		this->_secret_key = this->_original_secret_key;
	}

	[[nodiscard]]
	inline std::string name() const override
	{
		return this->_alg_name;
	}

	[[nodiscard]]
	std::function<std::string(const std::string&)> hash_function() const override;

private:
	std::string _secret_key;
	std::string _original_secret_key;
	const EVP_MD* (*_md)();
	const std::string _alg_name;
};

class HS256 : public HMAC
{
public:
	explicit HS256(std::string secret_key) :
		HMAC(std::move(secret_key), EVP_sha256, "HS256")
	{
	}
};

class HS384 : public HMAC
{
public:
	explicit HS384(std::string secret_key) :
		HMAC(std::move(secret_key), EVP_sha384, "HS384")
	{
	}
};

class HS512 : public HMAC
{
public:
	explicit HS512(std::string secret_key) :
		HMAC(std::move(secret_key), EVP_sha512, "HS512")
	{
	}
};

__CRYPTO_END__
