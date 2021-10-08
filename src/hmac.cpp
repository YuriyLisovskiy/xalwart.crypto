/**
 * hmac.cpp
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 */

#include "./hmac.h"

// OpenSSL libraries.
#include <openssl/hmac.h>

// Base libraries.
#include <xalwart.base/exceptions.h>


__CRYPTO_BEGIN__

std::string HmacSHA::sign(const std::string& data) const
{
	std::string res((size_t)EVP_MAX_MD_SIZE, '\0');
	auto len = (unsigned int)res.size();
	auto ret_value = HMAC(
		this->_md(),
		this->_secret_key.data(),
		(int)this->_secret_key.size(),
		(const unsigned char*)(data.data()),
		(int)data.size(),
		(unsigned char*)res.data(),
		&len
	);
	if (ret_value == nullptr)
	{
		throw RuntimeError("HMAC failed", _ERROR_DETAILS_);
	}

	res.resize(len);
	return res;
}

bool HmacSHA::verify(const std::string& data, const std::string& signature) const
{
	auto res = this->sign(data);
	if (res.size() != signature.size())
	{
		return false;
	}

	return res == signature;
}

__CRYPTO_END__
