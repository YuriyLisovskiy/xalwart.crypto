/**
 * tests_jwt.cpp
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 */

#include <gtest/gtest.h>

#include <xalwart.base/exceptions.h>

#include "../src/base64url.h"
#include "../src/jwt.h"
#include "../src/hmac.h"

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

TEST(TestCase_JWT, jwt_encode_ThrowsSignatureAlgorithmIsNullptr)
{
	ASSERT_THROW(crypto::jwt_encode(
		nullptr,
		{
			{"iat", 1633958000},
			{"exp", 1633962520}
		}
	), NullPointerException);
}

TEST(TestCase_JWT, jwt_encode_ThrowsPayloadIsNotJSONObject)
{
	auto signer = crypto::HS384("super-nano-secret-key");
	nlohmann::json payload(nlohmann::json::value_t::array);
	payload.push_back({"iat", 1633958000});
	payload.push_back({"exp", 1633962520});

	ASSERT_THROW(crypto::jwt_encode(&signer, payload), ArgumentError);
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

TEST(TestCase_JWT, jwt_verify_Success)
{
	std::string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.C5wrwhof-GoYas-LMHo65zF-UW_junfDuNXT_Hu1LcU";
	auto signer = crypto::HS256("my-256-bit-secret");

	ASSERT_TRUE(crypto::jwt_verify(token, &signer));
}

TEST(TestCase_JWT, jwt_verify_ThrowsSignatureAlgorithmIsNullptr)
{
	std::string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.C5wrwhof-GoYas-LMHo65zF-UW_junfDuNXT_Hu1LcU";

	ASSERT_THROW(crypto::jwt_verify(token, nullptr), NullPointerException);
}

TEST(TestCase_JWT, jwt_verify_ThrowsMissingTyp)
{
	std::string token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.3exNskjHmkI7-R48qReZh0dLEam3E0FEZd7DOwnprs8";
	auto signer = crypto::HS256("my-256-bit-secret");

	ASSERT_THROW(crypto::jwt_verify(token, &signer), ParseError);
}

TEST(TestCase_JWT, jwt_verify_ThrowsInvalidTyp)
{
	std::string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6Ik5PTi1KV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.1eMYpPfoCnL5d8F1UK9nwe8dNI4_FpTgNEMnkIj3CME";
	auto signer = crypto::HS256("my-256-bit-secret");

	ASSERT_THROW(crypto::jwt_verify(token, &signer), ParseError);
}

TEST(TestCase_JWT, jwt_verify_ThrowsMissingAlg)
{
	std::string token = "eyJ0eXAiOiJKV1QifQ.e30.FTp5vgoWK2wbyVypLJ-WbY4bfEgfZ5yc3RqCMlauRQM";
	auto signer = crypto::HS256("my-256-bit-secret");

	ASSERT_THROW(crypto::jwt_verify(token, &signer), ParseError);
}

TEST(TestCase_JWT, jwt_verify_ThrowsIncorrectAlgorithmUsed)
{
	std::string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.C5wrwhof-GoYas-LMHo65zF-UW_junfDuNXT_Hu1LcU";
	auto signer = crypto::HS384("my-256-bit-secret");

	ASSERT_THROW(crypto::jwt_verify(token, &signer), ArgumentError);
}

TEST(TestCase_JWT, jwt_verify_ThrowsPayloadIsNotJSONObject)
{
	std::string token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.W10.dhMmEQSWbd9p5TFJYlgR532Kxa4S-9wlPIqI5rWCWaM";
	auto signer = crypto::HS256("my-256-bit-secret");

	ASSERT_THROW(crypto::jwt_verify(token, &signer), ParseError);
}

TEST(TestCase_JWT, jwt_verify_VerificationFailedDueToIncorrectSecretKey)
{
	std::string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.C5wrwhof-GoYas-LMHo65zF-UW_junfDuNXT_Hu1LcU";
	auto signer = crypto::HS256("not-my-256-bit-secret");

	ASSERT_FALSE(crypto::jwt_verify(token, &signer));
}

TEST(TestCase_JWT, jwt_verify_VerificationFailedDueToNotOriginalPayload)
{
	std::string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.C5wrwhof-GoYas-LMHo65zF-UW_junfDuNXT_Hu1LcU";
	auto signer = crypto::HS256("my-256-bit-secret");

	ASSERT_FALSE(crypto::jwt_verify(token, &signer));
}

TEST(TestCase_JWT, jwt_verify_VerificationFailedDueToNotOriginalHeader)
{
	std::string token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.C5wrwhof-GoYas-LMHo65zF-UW_junfDuNXT_Hu1LcU";
	auto signer = crypto::HS384("my-256-bit-secret");

	ASSERT_FALSE(crypto::jwt_verify(token, &signer));
}
