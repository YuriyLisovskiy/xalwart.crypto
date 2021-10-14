/**
 * hmac.h
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 *
 * HMAC with SHA implementation.
 */

#pragma once

// STL libraries.
#include <string>
#include <functional>

// Module definitions.
#include "./_def_.h"

// Crypto libraries.
#include "./abc.h"
#include "./digest.h"


__CRYPTO_BEGIN__

class HMAC : public abc::ISignatureAlgorithm
{
public:
	inline HMAC(std::string secret_key, Digest digest, std::string alg_name) :
		_secret_key(std::move(secret_key)), _digest(std::move(digest)), _alg_name(std::move(alg_name))
	{
		this->_original_secret_key = this->_secret_key;
	}

	[[nodiscard]]
	std::string sign(const std::string& data) const override;

	[[nodiscard]]
	std::string sign_to_hex(const std::string& data) const override;

	[[nodiscard]]
	bool verify(const std::string& data, const std::string& signature) const override;

	inline void set_secret_key(const std::string& new_key) override
	{
		this->_secret_key = new_key;
	}

	inline void reset_secret_key() override
	{
		this->_secret_key = this->_original_secret_key;
	}

	[[nodiscard]]
	inline std::string get_name() const override
	{
		return this->_alg_name;
	}

	[[nodiscard]]
	inline std::function<std::string(const std::string&)> get_digest_function() const override
	{
		return this->_digest;
	}

private:
	std::string _secret_key;
	std::string _original_secret_key;
	Digest _digest;
	const std::string _alg_name;
};

class HS1 : public HMAC
{
public:
	explicit HS1(std::string secret_key) :
		HMAC(std::move(secret_key), sha1, "HS1")
	{
	}
};

class HS224 : public HMAC
{
public:
	explicit HS224(std::string secret_key) :
		HMAC(std::move(secret_key), sha224, "HS224")
	{
	}
};

class HS256 : public HMAC
{
public:
	explicit HS256(std::string secret_key) :
		HMAC(std::move(secret_key), sha256, "HS256")
	{
	}
};

class HS384 : public HMAC
{
public:
	explicit HS384(std::string secret_key) :
		HMAC(std::move(secret_key), sha384, "HS384")
	{
	}
};

class HS512 : public HMAC
{
public:
	explicit HS512(std::string secret_key) :
		HMAC(std::move(secret_key), sha512, "HS512")
	{
	}
};

__CRYPTO_END__
