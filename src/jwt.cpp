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
#include "./base64url.h"


__CRYPTO_JWT_BEGIN__

std::string sign(const ISignatureAlgorithm* algorithm, const nlohmann::json& claims)
{
	require_non_null(algorithm, "Signature algorithm is nullptr", _ERROR_DETAILS_);
	if (!claims.is_object())
	{
		throw ArgumentError("JWT payload should be JSON object", _ERROR_DETAILS_);
	}

	nlohmann::json header = {
		{"alg", algorithm->get_name()},
		{"typ", "JWT"}
	};
	std::string unsigned_token = base64url_encode(header.dump()) + "."
		+ base64url_encode(claims.dump());
	std::string signature = algorithm->sign(unsigned_token);
	return unsigned_token + "." + base64url_encode(signature);
}

std::tuple<std::string, std::string, std::string> split(const std::string& token)
{
	// header, payload, signature
	auto parts = str::split(token, '.', 2);
	if (parts.size() != 3)
	{
		throw ArgumentError("Invalid JWT", _ERROR_DETAILS_);
	}

	return {parts[0], parts[1], parts[2]};
}

std::tuple<nlohmann::json, nlohmann::json, std::string> decode(const std::string& token)
{
	auto [header, payload, signature] = split(token);
	return {
		nlohmann::json::parse(base64url_decode(header)),
		nlohmann::json::parse(base64url_decode(payload)),
		base64url_decode(signature)
	};
}

bool verify_signature(
	const ISignatureAlgorithm* algorithm, const std::string& token, std::string signature
)
{
	require_non_null(algorithm, "Signature algorithm is nullptr", _ERROR_DETAILS_);
	auto data = split(token);
	if (signature.empty())
	{
		signature = base64url_decode(std::get<2>(data));
	}

	return algorithm->verify(std::get<0>(data) + "." + std::get<1>(data), signature);
}

bool verify_audience(const nlohmann::json& claims, const std::vector<std::string>& target_audience)
{
	if (!target_audience.empty() && claims.contains(aud))
	{
		auto audience = claims[aud];
		if (audience.is_array())
		{
			for (const auto& target : target_audience)
			{
				if (std::find(audience.begin(),  audience.end(), target) == audience.end())
				{
					return false;
				}
			}
		}
	}

	return true;
}

void _validate(
	const nlohmann::json& header, const nlohmann::json& payload, const ISignatureAlgorithm* algorithm
)
{
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

	if (header["alg"].get<std::string>() != algorithm->get_name())
	{
		throw ArgumentError("Got incorrect signature algorithm", _ERROR_DETAILS_);
	}

	if (!payload.is_object())
	{
		throw ParseError("JWT payload is not JSON object", _ERROR_DETAILS_);
	}
}

__CRYPTO_JWT_END__
