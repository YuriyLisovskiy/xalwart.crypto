/**
 * tests_digest.cpp
 *
 * Copyright (c) 2021 Yuriy Lisovskiy
 */

#include <gtest/gtest.h>

#include "../src/digest.h"

using namespace xw;


TEST(TestCase_BLAKE, blake2b512_EmptyString)
{
	auto actual = crypto::blake2b512("");
	std::string expected = "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_BLAKE, blake2b512)
{
	auto actual = crypto::blake2b512("hello, world");
	std::string expected = "7355dd5276c21cfe0c593b5063b96af3f96a454b33216f58314f44c3ade92e9cd6cec4210a0836246780e9baf927cc50b9a3d7073e8f9bd12780fddbcb930c6d";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_BLAKE, blake2s256_EmptyString)
{
	auto actual = crypto::blake2s256("");
	std::string expected = "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_BLAKE, blake2s256)
{
	auto actual = crypto::blake2s256("hello, world");
	std::string expected = "4f303036dc58e3c7bf38d48293c6e0f0404e986be5bfe62eb4eae8e8d30dd828";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_MD, md5_EmptyString)
{
	auto actual = crypto::md5("");
	std::string expected = "d41d8cd98f00b204e9800998ecf8427e";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_MD, md5)
{
	auto actual = crypto::md5("hello, world");
	std::string expected = "e4d7f1b4ed2e42d15898f4b27b019da4";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_SHA, sha1_EmptyString)
{
	auto actual = crypto::sha1("");
	std::string expected = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_SHA, sha1)
{
	auto actual = crypto::sha1("hello, world");
	std::string expected = "b7e23ec29af22b0b4e41da31e868d57226121c84";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_SHA, sha3_384_EmptyString)
{
	auto actual = crypto::sha3_384("");
	std::string expected = "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_SHA, sha3_384)
{
	auto actual = crypto::sha3_384("hello, world");
	std::string expected = "fbd0c5931195aaa9517869972b372f717bb69f7f9f72bfc0884ed0531c36a16fc2db5dd6d82131968b23ffe0e90757e5";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_SHA, sha384_EmptyString)
{
	auto actual = crypto::sha384("");
	std::string expected = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_SHA, sha384)
{
	auto actual = crypto::sha384("hello, world");
	std::string expected = "1fcdb6059ce05172a26bbe2a3ccc88ed5a8cd5fc53edfd9053304d429296a6da23b1cd9e5c9ed3bb34f00418a70cdb7e";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_SHA, sha256_EmptyString)
{
	auto actual = crypto::sha256("");
	std::string expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_SHA, sha256)
{
	auto actual = crypto::sha256("hello, world");
	std::string expected = "09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_SHA, sha512_EmptyString)
{
	auto actual = crypto::sha512("");
	std::string expected = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_SHA, sha512)
{
	auto actual = crypto::sha512("hello, world");
	std::string expected = "8710339dcb6814d0d9d2290ef422285c9322b7163951f9a0ca8f883d3305286f44139aa374848e4174f5aada663027e4548637b6d19894aec4fb6c46a139fbf9";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_SHA, sha3_256_EmptyString)
{
	auto actual = crypto::sha3_256("");
	std::string expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_SHA, sha3_256)
{
	auto actual = crypto::sha3_256("hello, world");
	std::string expected = "bfb3959527d7a3f2f09def2f6915452d55a8f122df9e164d6f31c7fcf6093e14";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_SHA, sha3_512_EmptyString)
{
	auto actual = crypto::sha3_512("");
	std::string expected = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_SHA, sha3_512)
{
	auto actual = crypto::sha3_512("hello, world");
	std::string expected = "2ed3a863a12e2f8ff140aa86232ff3603a7f24af62f0e2ca74672494ade175a9a3de42a351b5019d931a1deae0499609038d9b47268779d76198e1d410d20974";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_SHA, sha3_224_EmptyString)
{
	auto actual = crypto::sha3_224("");
	std::string expected = "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_SHA, sha3_224)
{
	auto actual = crypto::sha3_224("hello, world");
	std::string expected = "927b362eaf84a75785bbec3370d1c9711349e93f1104eda060784221";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_SHA, sha224_EmptyString)
{
	auto actual = crypto::sha224("");
	std::string expected = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_SHA, sha224)
{
	auto actual = crypto::sha224("hello, world");
	std::string expected = "6e1a93e32fb44081a401f3db3ef2e6e108b7bbeeb5705afdaf01fb27";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_SHA, shake_128_EmptyString)
{
	auto actual = crypto::shake128("");
	std::string expected = "7f9c2ba4e88f827d616045507605853e";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_SHA, shake_128)
{
	auto actual = crypto::shake128("hello, world");
	std::string expected = "83d41db453072caa9953f2f316480fbb";
	ASSERT_EQ(expected, actual);
}
TEST(TestCase_SHA, shake_256_EmptyString)
{
	auto actual = crypto::shake256("");
	std::string expected = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f";
	ASSERT_EQ(expected, actual);
}

TEST(TestCase_SHA, shake256)
{
	auto actual = crypto::shake256("hello, world");
	std::string expected = "7c9896ea84a2a1b80b2183a3f2b4e43cd59b7d48471dc213bcedaccb699d6e6f";
	ASSERT_EQ(expected, actual);
}
