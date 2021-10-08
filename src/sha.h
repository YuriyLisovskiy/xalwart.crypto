/**
 * sha.h
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 *
 * SHA hash functions adaptation from openssl library.
 */

#pragma once

// C++ libraries.
#include <string>

// Module definitions.
#include "./_def_.h"


__CRYPTO_BEGIN__

std::string sha256(const std::string& data);

__CRYPTO_END__
