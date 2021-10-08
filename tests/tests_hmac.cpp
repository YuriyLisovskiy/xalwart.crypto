/**
 * tests_sha.cpp
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 */

#include <gtest/gtest.h>

#include "../src/hmac.h"

using namespace xw;


TEST(TestCase_HS256, success)
{
	std::string data = "hello, world";
	std::string secret = "secret";
	crypto::HS256 hs256(secret);
	auto signature = hs256.sign(data);

	ASSERT_TRUE(hs256.verify(data, signature));
}

TEST(TestCase_HS256, fail_InvalidData)
{
	std::string data = "hello, world";
	std::string secret = "secret";
	crypto::HS256 hs256(secret);
	auto signature = hs256.sign(data);

	ASSERT_FALSE(hs256.verify(data + "some additional data", signature));
}

TEST(TestCase_HS256, fail_InvalidKey)
{
	std::string data = "hello, world";
	std::string secret = "secret";
	auto signature = crypto::HS256(secret).sign(data);

	ASSERT_FALSE(
		crypto::HS256("another key").verify(data + "some additional data", signature)
	);
}

TEST(TestCase_HS384, success)
{
	std::string data = "hello, world";
	std::string secret = "secret";
	crypto::HS384 hs384(secret);
	auto signature = hs384.sign(data);

	ASSERT_TRUE(hs384.verify(data, signature));
}

TEST(TestCase_HS384, fail_InvalidData)
{
	std::string data = "hello, world";
	std::string secret = "secret";
	crypto::HS384 hs384(secret);
	auto signature = hs384.sign(data);

	ASSERT_FALSE(hs384.verify(data + "some additional data", signature));
}

TEST(TestCase_HS384, fail_InvalidKey)
{
	std::string data = "hello, world";
	std::string secret = "secret";
	auto signature = crypto::HS384(secret).sign(data);

	ASSERT_FALSE(
		crypto::HS384("another key").verify(data + "some additional data", signature)
	);
}

TEST(TestCase_HS512, success)
{
	std::string data = "hello, world";
	std::string secret = "secret";
	crypto::HS512 hs512(secret);
	auto signature = hs512.sign(data);

	ASSERT_TRUE(hs512.verify(data, signature));
}

TEST(TestCase_HS512, fail_InvalidData)
{
	std::string data = "hello, world";
	std::string secret = "secret";
	crypto::HS512 hs512(secret);
	auto signature = hs512.sign(data);

	ASSERT_FALSE(hs512.verify(data + "some additional data", signature));
}

TEST(TestCase_HS512, fail_InvalidKey)
{
	std::string data = "hello, world";
	std::string secret = "secret";
	auto signature = crypto::HS512(secret).sign(data);

	ASSERT_FALSE(
		crypto::HS512("another key").verify(data + "some additional data", signature)
	);
}
