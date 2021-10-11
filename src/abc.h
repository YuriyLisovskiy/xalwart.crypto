/**
 * abc.h
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 *
 * Abstract base classes for crypto library.
 */

#pragma once

// STL Libraries.
#include <string>
#include <functional>

// Module definitions.
#include "./_def_.h"


__CRYPTO_ABC_BEGIN__

class ISignatureAlgorithm
{
public:
	[[nodiscard]]
	virtual std::string sign(const std::string& data) const = 0;

	[[nodiscard]]
	virtual std::string sign_to_hex(const std::string& data) const = 0;

	[[nodiscard]]
	virtual bool verify(const std::string& data, const std::string& signature) const = 0;

	virtual void update_secret_key(const std::string& new_key) = 0;

	virtual void reset_secret_key() = 0;

	[[nodiscard]]
	virtual std::string name() const = 0;

	[[nodiscard]]
	virtual std::function<std::string(const std::string&)> hash_function() const = 0;
};

__CRYPTO_ABC_END__
