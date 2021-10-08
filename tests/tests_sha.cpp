/**
 * tests_sha.cpp
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 */

#include <gtest/gtest.h>

#include "../src/sha.h"

using namespace xw;


TEST(TestCase_Sha, sha256_EmptyString)
{
	auto actual = xw::crypto::sha256("");
	std::string expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_Sha, sha256)
{
	auto actual = xw::crypto::sha256("hello, world");
	std::string expected = "09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b";
	ASSERT_EQ(expected, actual);
}
