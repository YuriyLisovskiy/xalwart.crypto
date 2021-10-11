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

std::string jwt_encode(const abc::ISignatureAlgorithm* algorithm, const nlohmann::json& payload)
{
	require_non_null(algorithm, "Signature algorithm is nullptr", _ERROR_DETAILS_);
	if (!payload.is_object())
	{
		throw ArgumentError("JWT payload should be JSON object", _ERROR_DETAILS_);
	}

	nlohmann::json header = {
		{"alg", algorithm->name()},
		{"typ", "JWT"}
	};
	std::string unsigned_token = base64url_encode(header.dump()) + "."
		+ base64url_encode(payload.dump());
	std::string signature = algorithm->sign(unsigned_token);
	return unsigned_token + "." + base64url_encode(signature);
}

std::tuple<nlohmann::json, nlohmann::json, std::string> jwt_decode(const std::string& token)
{
	// header, payload, signature
	auto parts = str::split(token, '.', 2);
	if (parts.size() != 3)
	{
		throw ArgumentError("Invalid JWT structure", _ERROR_DETAILS_);
	}

	return {
		nlohmann::json::parse(base64url_decode(parts[0])),
		nlohmann::json::parse(base64url_decode(parts[1])),
		base64url_decode(parts[2])
	};
}

bool jwt_verify(const std::string& token, const abc::ISignatureAlgorithm* algorithm)
{
	require_non_null(algorithm, "Signature algorithm is nullptr", _ERROR_DETAILS_);
	auto [header, payload, signature] = jwt_decode(token);
	if (!header.contains("typ"))
	{
		throw ParseError("Invalid JWT header: missing typ", _ERROR_DETAILS_);
	}

	if (header["typ"].get<std::string>() != "JWT")
	{
		throw ParseError("Invalid JWT typ", _ERROR_DETAILS_);
	}

	if (!header.contains("alg"))
	{
		throw ParseError("Invalid JWT header: missing alg", _ERROR_DETAILS_);
	}

	auto alg = header["alg"].get<std::string>();
	if (alg != algorithm->name())
	{
		throw ArgumentError("Got incorrect signature algorithm", _ERROR_DETAILS_);
	}

	if (!payload.is_object())
	{
		throw ParseError("JWT payload is not JSON object", _ERROR_DETAILS_);
	}

	auto data_to_verify = str::rsplit(token, '.', 1);
	return algorithm->verify(data_to_verify[0], signature);
}

__CRYPTO_END__
