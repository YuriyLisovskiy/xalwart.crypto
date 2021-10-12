/**
 * utilities.h
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 *
 * Crypto utilities.
 */

#pragma once

// STL libraries.
#include <string>

// OpenSSL libraries.
#include <openssl/evp.h>

// Module definitions.
#include "./_def_.h"


__CRYPTO_BEGIN__

extern std::string hex_digest(const EVP_MD* (*md)(), const std::string& data);

__CRYPTO_END__
