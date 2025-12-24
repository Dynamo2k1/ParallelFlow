// Unit tests for Aho-Corasick pattern matching

#include <gtest/gtest.h>
#include "aho_corasick.h"
#include <string>
#include <vector>

namespace {

class AhoCorasickTest : public ::testing::Test {
protected:
    AhoCorasick ac;
};

TEST_F(AhoCorasickTest, NotBuiltIsEmpty) {
    EXPECT_FALSE(ac.built());
    auto matches = ac.search("test", 4);
    EXPECT_TRUE(matches.empty());
}

TEST_F(AhoCorasickTest, SingleKeywordMatch) {
    std::vector<std::string> keywords = {"hello"};
    ac.build(keywords);
    EXPECT_TRUE(ac.built());
    
    std::string text = "say hello world";
    auto matches = ac.search(text.data(), text.size());
    
    EXPECT_EQ(matches.size(), 1u);
    EXPECT_EQ(matches[0].keyword_id, 0);
}

TEST_F(AhoCorasickTest, SingleKeywordNoMatch) {
    std::vector<std::string> keywords = {"hello"};
    ac.build(keywords);
    
    std::string text = "goodbye world";
    auto matches = ac.search(text.data(), text.size());
    
    EXPECT_TRUE(matches.empty());
}

TEST_F(AhoCorasickTest, MultipleKeywordsMatch) {
    std::vector<std::string> keywords = {"password", "secret", "api_key"};
    ac.build(keywords);
    
    std::string text = "user=admin&password=123&api_key=xyz";
    auto matches = ac.search(text.data(), text.size());
    
    EXPECT_EQ(matches.size(), 2u);
}

TEST_F(AhoCorasickTest, OverlappingKeywords) {
    std::vector<std::string> keywords = {"ab", "abc", "bc"};
    ac.build(keywords);
    
    std::string text = "abc";
    auto matches = ac.search(text.data(), text.size());
    
    // Should match all three: "ab" at pos 1, "abc" at pos 2, "bc" at pos 2
    EXPECT_GE(matches.size(), 3u);
}

TEST_F(AhoCorasickTest, MaxMatchesLimit) {
    std::vector<std::string> keywords = {"a"};
    ac.build(keywords);
    
    std::string text = "aaaaaaaaaa"; // 10 'a's
    auto matches = ac.search(text.data(), text.size(), 3);
    
    EXPECT_EQ(matches.size(), 3u);
}

TEST_F(AhoCorasickTest, EmptyText) {
    std::vector<std::string> keywords = {"hello"};
    ac.build(keywords);
    
    std::string text = "";
    auto matches = ac.search(text.data(), text.size());
    
    EXPECT_TRUE(matches.empty());
}

TEST_F(AhoCorasickTest, EmptyKeywords) {
    std::vector<std::string> keywords = {};
    ac.build(keywords);
    EXPECT_TRUE(ac.built());
    
    std::string text = "hello world";
    auto matches = ac.search(text.data(), text.size());
    
    EXPECT_TRUE(matches.empty());
}

TEST_F(AhoCorasickTest, BinaryData) {
    std::vector<std::string> keywords = {"\x00\x01", "\xff\xfe"};
    ac.build(keywords);
    
    std::string text = "prefix\x00\x01suffix";
    auto matches = ac.search(text.data(), text.size());
    
    EXPECT_GE(matches.size(), 1u);
}

TEST_F(AhoCorasickTest, SecurityKeywords) {
    std::vector<std::string> keywords = {
        "powershell",
        "cmd.exe",
        "/etc/passwd",
        "SELECT * FROM",
        "eval("
    };
    ac.build(keywords);
    
    std::string text = "GET /cmd.exe?q=test HTTP/1.1";
    auto matches = ac.search(text.data(), text.size());
    
    EXPECT_EQ(matches.size(), 1u);
    EXPECT_EQ(ac.keywords()[matches[0].keyword_id], "cmd.exe");
}

} // namespace
