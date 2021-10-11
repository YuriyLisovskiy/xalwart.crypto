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

// Base libraries.
#include <xalwart.base/vendor/nlohmann/json.h>

// Module definitions.
#include "./_def_.h"

// Crypto libraries.
#include "./abc.h"


__CRYPTO_BEGIN__

// TODO: docs for 'jwt_encode'
extern std::string jwt_encode(const abc::ISignatureAlgorithm* algorithm, const nlohmann::json& payload);

// TODO: docs for 'jwt_decode'
// Returns [header, payload, signature]
extern std::tuple<nlohmann::json, nlohmann::json, std::string> jwt_decode(const std::string& token);

// TODO: docs for 'jwt_verify'
extern bool jwt_verify(const std::string& token, const abc::ISignatureAlgorithm* algorithm);

__CRYPTO_END__
