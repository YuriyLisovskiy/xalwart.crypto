/**
 * tests_jwt.cpp
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 */

#include <gtest/gtest.h>

#include "../src/base64.h"
#include "../src/jwt.h"

using namespace xw;


TEST(TestCase_JWT, jwt_encode_EmptyPayload)
{
	auto signer = crypto::HS256("super-nano-secret-key");
	auto actual = crypto::jwt_encode(&signer, nlohmann::json(nlohmann::json::value_t::object));
	std::string expected = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.thR_wiUHZa5vNMX0KaXTMqJUm1tkWRp2cQgqlfHK740";

	ASSERT_EQ(actual, expected);
}

TEST(TestCase_JWT, jwt_encode)
{
	auto signer = crypto::HS384("super-nano-secret-key");
	auto actual = crypto::jwt_encode(
		&signer,
		{
			{"iat", 1633958000},
			{"exp", 1633962520}
		}
	);
	std::string expected = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MzM5NjI1MjAsImlhdCI6MTYzMzk1ODAwMH0.DjdVea5eqIDmSqqhqbu68D63U_9LbSUHWRtWjEHXtgnL6guTdgtvLxkEwzIU14M0";

	ASSERT_EQ(actual, expected);
}

TEST(TestCase_JWT, jwt_decode)
{
	auto [header, payload, signature] = crypto::jwt_decode(
		"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MzM5NjI1MjAsImlhdCI6MTYzMzk1ODIyMn0.4pYaSz4Z3eqfgGVF2bwp2H73bT4Uz3nZcu7MuXr9x82ZHAuMIeTFbnsqY98g8EjenB-fJ3HN9Kp43XDieB_3fg"
	);

	ASSERT_EQ(header["alg"].get<std::string>(), "HS512");
	ASSERT_EQ(header["typ"].get<std::string>(), "JWT");

	ASSERT_EQ(payload["exp"].get<size_t>(), 1633962520);
	ASSERT_EQ(payload["iat"].get<size_t>(), 1633958222);

	ASSERT_EQ(
		signature,
		crypto::base64url_decode("4pYaSz4Z3eqfgGVF2bwp2H73bT4Uz3nZcu7MuXr9x82ZHAuMIeTFbnsqY98g8EjenB-fJ3HN9Kp43XDieB_3fg")
	);
}

TEST(TestCase_JWT, jwt_decode_ThrowsInvalidPartsCount)
{
	ASSERT_THROW(crypto::jwt_decode(
		"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MzM5NjI1MjAsImlhdCI6MTYzMzk1ODIyMn0"
	), ArgumentError);
}

TEST(TestCase_JWT, jwt_decode_NoThrowsOnMoreThanThreeParts)
{
	ASSERT_NO_THROW(crypto::jwt_decode(
		"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MzM5NjI1MjAsImlhdCI6MTYzMzk1ODIyMn0.4pYaSz4Z3eqfgGVF2bwp2H73bT4Uz3nZcu7MuXr9x82ZHAuMIeTFbnsqY98g8EjenB-fJ3HN9Kp43XDieB_3fg.eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9"
	));
}
