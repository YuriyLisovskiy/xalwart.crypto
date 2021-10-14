/**
 * base64url.h
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 *
 * Base64 translates 24 bits into 4 ASCII characters at a time. First,
 * 3 8-bit bytes are treated as 4 6-bit groups. Those 4 groups are
 * translated into ASCII characters. That is, each 6-bit number is treated
 * as an index into the ASCII character array.
 *
 * If the final set of bits is less 8 or 16 instead of 24, traditional base64
 * would add a padding character. However, if the length of the data is
 * known, then padding can be eliminated.
 *
 * One difference between the "standard" Base64 is two characters are different.
 * See RFC 4648 for details.
 * This is how we end up with the Base64 URL encoding.
*/

#pragma once

// STL Libraries.
#include <string>

// Module definitions.
#include "./_def_.h"


__CRYPTO_BEGIN__

extern std::string base64url_encode(const std::string& raw_data);

extern std::string base64url_decode(const std::string& encoded_data);

__CRYPTO_END__
