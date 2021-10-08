/**
 * sha.cpp
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 */

#include "./sha.h"

// STL libraries.
#include <iomanip>
#include <sstream>

// OpenSSL libraries.
#include <openssl/sha.h>


__CRYPTO_BEGIN__

std::string sha256(const std::string& data)
{
	unsigned char md[SHA256_DIGEST_LENGTH];
	auto digest = SHA256((const unsigned char*)(data.c_str()), data.size(), (unsigned char*)(&md));
	std::stringstream ss;
	for(auto i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
	}

	return ss.str();
}

__CRYPTO_END__
