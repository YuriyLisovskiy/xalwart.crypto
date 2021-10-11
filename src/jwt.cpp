/**
 * jwt.cpp
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 */

#include "./jwt.h"

// Base libraries.
#include <xalwart.base/string_utils.h>
#include <xalwart.base/exceptions.h>

// Crypto libraries.
#include "./base64.h"


__CRYPTO_BEGIN__

std::string jwt_encode(const HMAC* signer, const nlohmann::json& payload)
{
	require_non_null(signer, "HMAC signer is nullptr", _ERROR_DETAILS_);
	nlohmann::json header = {
		{"alg", signer->name()},
		{"typ", "JWT"}
	};
	std::string unsigned_token = base64url_encode(header.dump()) + "."
		+ base64url_encode(payload.dump());
	std::string signature = signer->sign(unsigned_token);
	return unsigned_token + "." + base64url_encode(signature);
}

std::tuple<nlohmann::json, nlohmann::json, std::string> jwt_decode(const std::string& token)
{
	// header, payload, signature
	auto parts = str::split(token, '.', 2);
	if (parts.size() != 3)
	{
		throw ArgumentError("Unable to split JWT", _ERROR_DETAILS_);
	}

	return {
		nlohmann::json::parse(base64url_decode(parts[0])),
		nlohmann::json::parse(base64url_decode(parts[1])),
		base64url_decode(parts[2])
	};
}

__CRYPTO_END__
