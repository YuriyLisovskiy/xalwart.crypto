/**
 * digest.cpp
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 */

#include "./digest.h"

// STL libraries.
#include <sstream>
#include <iomanip>


__CRYPTO_BEGIN__

std::string _hex_digest(const EVP_MD* md, const std::string& data)
{
	if (!md)
	{
		throw NullPointerException("const EVP_MD* (*md)() is nullptr", _ERROR_DETAILS_);
	}

	EVP_MD_CTX* md_ctx = EVP_MD_CTX_create();
	if(!EVP_DigestInit_ex(md_ctx, md, nullptr))
	{
		throw RuntimeError("EVP_DigestInit_ex: failed", _ERROR_DETAILS_);
	}

	if(!EVP_DigestUpdate(md_ctx, (const void*)data.data(), data.size()))
	{
		throw RuntimeError("EVP_DigestUpdate: failed", _ERROR_DETAILS_);
	}

	unsigned int md_len = 0;
	unsigned char digest[EVP_MAX_MD_SIZE];
	if(!EVP_DigestFinal_ex(md_ctx, digest, &md_len))
	{
		throw RuntimeError("EVP_DigestFinal_ex: failed", _ERROR_DETAILS_);
	}

	EVP_MD_CTX_destroy(md_ctx);
	std::stringstream ss;
	for(auto i = 0; i < md_len; i++)
	{
		ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
	}

	return ss.str();
}

Digest new_digest(const std::string& name)
{
	return Digest{[name]() -> const EVP_MD*
	{
		auto* md = EVP_get_digestbyname(name.c_str());
		if (!md)
		{
			throw NullPointerException(
				"EVP_get_digestbyname: digest not found not found", _ERROR_DETAILS_
			);
		}

		return md;
	}};
}

__CRYPTO_END__
