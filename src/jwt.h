/**
 * jwt.h
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 *
 * JSON Web Token implementation.
 */

#pragma once

// STL Libraries.
#include <string>
#include <tuple>
#include <vector>

// Base libraries.
#include <xalwart.base/vendor/nlohmann/json.h>

// Module definitions.
#include "./_def_.h"

// Crypto libraries.
#include "./interfaces.h"


__CRYPTO_JWT_BEGIN__

// (issuer): Issuer of the JWT.
constexpr const char* iss = "iss";

// (subject): Subject of the JWT (the user).
constexpr const char* sub = "sub";

// (audience): Recipient for which the JWT is intended.
constexpr const char* aud = "aud";

// (expiration time): Time after which the JWT expires.
constexpr const char* exp = "exp";

// (not before time): Time before which the JWT must not be accepted for processing.
constexpr const char* nbf = "nbf";

// (issued at time): Time at which the JWT was issued; can be used to determine age of the JWT.
constexpr const char* iat = "iat";

// (JWT ID): Unique identifier; can be used to prevent the JWT from being replayed (allows a
// token to be used only once).
constexpr const char* jti = "jti";

// TODO: docs for 'sign'
extern std::string sign(const ISignatureAlgorithm* algorithm, const nlohmann::json& claims);

// TESTME: split
// TODO: docs for 'split'
// Returns base64url encoded parts: [header, payload, signature]
// Throws ArgumentError on invalid JWT.
extern std::tuple<std::string, std::string, std::string> split(const std::string& token);

// TODO: docs for 'decode'
// Returns [header, claims, signature]
extern std::tuple<nlohmann::json, nlohmann::json, std::string> decode(const std::string& token);

// TESTME: verify_signature
// TODO: docs for 'verify_signature'
extern bool verify_signature(
	const ISignatureAlgorithm* algorithm, const std::string& token, std::string signature=""
);

// TESTME: verify_audience
// TODO: docs for 'verify_audience'
extern bool verify_audience(const nlohmann::json& claims, const std::vector<std::string>& target_audience);

// TESTME: _validate
// TODO: docs for '_validate'
void _validate(
	const nlohmann::json& header, const nlohmann::json& payload, const ISignatureAlgorithm* algorithm
);

__CRYPTO_JWT_END__
