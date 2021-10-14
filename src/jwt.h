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
#include "./abc.h"


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
extern std::string sign(const abc::ISignatureAlgorithm* algorithm, const nlohmann::json& payload);

// TODO: docs for 'decode'
// Returns [header, payload, signature]
extern std::tuple<nlohmann::json, nlohmann::json, std::string> decode(const std::string& token);

// TESTME: verify
// TODO: docs for 'verify'
// Returns [payload, is_verified]
extern std::tuple<nlohmann::json, bool> verify(
	const std::string& token, const abc::ISignatureAlgorithm* algorithm
);

// TESTME: verify_audience
// TODO: docs for 'verify_audience'
extern bool verify_audience(const nlohmann::json& claims, const std::vector<std::string>& target_audience);

// TESTME: _validate
// TODO: docs for '_validate'
void _validate(
	const nlohmann::json& header, const nlohmann::json& payload, const abc::ISignatureAlgorithm* algorithm
);

__CRYPTO_JWT_END__
