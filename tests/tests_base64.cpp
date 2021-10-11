/**
 * tests_base64.cpp
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 */

#include <gtest/gtest.h>

#include "../src/base64.h"

using namespace xw;


TEST(TestCase_Encoding, base64url_encode_EmptyString)
{
	auto actual = xw::crypto::base64url_encode("");
	std::string expected;
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_Encoding, base64url_encode)
{
	auto actual = xw::crypto::base64url_encode("hello, world \\uD83D\\uDE03");
	std::string expected = "aGVsbG8sIHdvcmxkIFx1RDgzRFx1REUwMw";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_Encoding, base64url_decode_EmptyString)
{
	auto actual = xw::crypto::base64url_decode("");
	std::string expected;
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_Encoding, base64url_decode)
{
	auto actual = xw::crypto::base64url_decode("aGVsbG8sIHdvcmxkIPCfmIM=");
	std::string expected = "hello, world \xF0\x9F\x98\x83";
	ASSERT_EQ(expected, actual);
}
