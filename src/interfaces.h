/**
 * interfaces.h
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 *
 * Interfaces for crypto library.
 */

#pragma once

// STL Libraries.
#include <string>
#include <functional>

// Module definitions.
#include "./_def_.h"


__CRYPTO_BEGIN__

class ISignatureAlgorithm
{
public:
	virtual ~ISignatureAlgorithm() = default;

	[[nodiscard]]
	virtual std::string sign(const std::string& data) const = 0;

	[[nodiscard]]
	virtual std::string sign_to_hex(const std::string& data) const = 0;

	[[nodiscard]]
	virtual bool verify(const std::string& data, const std::string& signature) const = 0;

	virtual void set_secret_key(const std::string& new_key) = 0;

	virtual void reset_secret_key() = 0;

	[[nodiscard]]
	virtual std::string get_name() const = 0;

	[[nodiscard]]
	virtual std::function<std::string(const std::string&)> get_digest_function() const = 0;
};

__CRYPTO_END__
