/**
 * hmac.cpp
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 */

#include "./hmac.h"

// STL libraries.
#include <iomanip>
#include <sstream>

// OpenSSL libraries.
#include <openssl/evp.h>
#include <openssl/hmac.h>

// Base libraries.
#include <xalwart.base/exceptions.h>
#include <xalwart.base/string_utils.h>


__CRYPTO_BEGIN__

std::string HMAC::sign(const std::string& data) const
{
	std::string signature((size_t)EVP_MAX_MD_SIZE, '\0');
	auto len = (unsigned int)signature.size();
	auto ret_value = ::HMAC(
		this->_digest.evp_md(),
		this->_secret_key.data(),
		(int)this->_secret_key.size(),
		(const unsigned char*)(data.data()),
		(int)data.size(),
		(unsigned char*)signature.data(),
		&len
	);
	if (ret_value == nullptr)
	{
		throw RuntimeError("HMAC failed", _ERROR_DETAILS_);
	}

	signature.resize(len);
	return signature;
}

std::string HMAC::sign_to_hex(const std::string& data) const
{
	auto signature = this->sign(data);
	std::ostringstream ss;
	ss << std::hex << std::uppercase << std::setfill('0');
	for (unsigned char c : signature)
	{
		ss << std::setw(2) << (int)c;
	}

	return ss.str();
}

bool HMAC::verify(const std::string& data, const std::string& signature) const
{
	auto res = this->sign(data);
	if (res.size() != signature.size())
	{
		return false;
	}

	return res == signature;
}

std::shared_ptr<ISignatureAlgorithm> get_hs_signer(
	const std::string& name, const std::string& secret_key
)
{
	std::shared_ptr<ISignatureAlgorithm> algorithm = nullptr;
	auto upper_name = str::to_upper(name);
	if (upper_name == "HS1")
	{
		algorithm = std::make_shared<HS1>(secret_key);
	}
	else if (upper_name == "HS224")
	{
		algorithm = std::make_shared<HS224>(secret_key);
	}
	else if (upper_name == "HS256")
	{
		algorithm = std::make_shared<HS256>(secret_key);
	}
	else if (upper_name == "HS384")
	{
		algorithm = std::make_shared<HS384>(secret_key);
	}
	else if (upper_name == "HS512")
	{
		algorithm = std::make_shared<HS512>(secret_key);
	}
	else
	{
		throw ArgumentError("HMAC-SHA algorithm not found: " + name, _ERROR_DETAILS_);
	}

	return algorithm;
}

__CRYPTO_END__
