/**
 * tests_md.cpp
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 */

#include <gtest/gtest.h>

#include "../src/md.h"

using namespace xw;


TEST(TestCase_MD, md5_EmptyString)
{
	auto actual = xw::crypto::md5("");
	std::string expected = "d41d8cd98f00b204e9800998ecf8427e";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_MD, md5)
{
	auto actual = xw::crypto::md5("hello, world");
	std::string expected = "e4d7f1b4ed2e42d15898f4b27b019da4";
	ASSERT_EQ(expected, actual);
}
