/**
 * _def_.h
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 *
 * Definitions of main module.
 */

#pragma once

// Module definitions.
#include <xalwart.base/_def_.h>

// xw::crypto
#define __CRYPTO_BEGIN__ __MAIN_NAMESPACE_BEGIN__ namespace crypto {
#define __CRYPTO_END__ } __MAIN_NAMESPACE_END__

// xw::crypto::jwt
#define __CRYPTO_JWT_BEGIN__ __CRYPTO_BEGIN__ namespace jwt {
#define __CRYPTO_JWT_END__ } __CRYPTO_END__


__CRYPTO_BEGIN__

namespace v
{
	inline const auto version = Version("0.0.0");
};

__CRYPTO_END__
