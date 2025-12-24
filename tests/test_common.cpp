// Unit tests for common utility functions

#include <gtest/gtest.h>
#include "common.h"
#include <string>

namespace {

TEST(TrimTest, EmptyString) {
    EXPECT_EQ(util::trim(""), "");
}

TEST(TrimTest, WhitespaceOnly) {
    EXPECT_EQ(util::trim("   "), "");
    EXPECT_EQ(util::trim("\t\n"), "");
}

TEST(TrimTest, LeadingWhitespace) {
    EXPECT_EQ(util::trim("  hello"), "hello");
    EXPECT_EQ(util::trim("\thello"), "hello");
}

TEST(TrimTest, TrailingWhitespace) {
    EXPECT_EQ(util::trim("hello  "), "hello");
    EXPECT_EQ(util::trim("hello\n"), "hello");
}

TEST(TrimTest, BothEnds) {
    EXPECT_EQ(util::trim("  hello  "), "hello");
    EXPECT_EQ(util::trim("\t hello world \n"), "hello world");
}

TEST(StartsWithTest, Basic) {
    EXPECT_TRUE(util::starts_with("hello world", "hello"));
    EXPECT_TRUE(util::starts_with("hello", "hello"));
    EXPECT_FALSE(util::starts_with("hello", "world"));
    EXPECT_TRUE(util::starts_with("anything", ""));
}

TEST(ToLowerTest, Basic) {
    EXPECT_EQ(util::to_lower("HELLO"), "hello");
    EXPECT_EQ(util::to_lower("Hello World"), "hello world");
    EXPECT_EQ(util::to_lower("123ABC"), "123abc");
    EXPECT_EQ(util::to_lower(""), "");
}

TEST(IpToStringTest, Basic) {
    // 127.0.0.1 in network byte order (big endian)
    uint32_t localhost_be = 0x0100007F; // 127.0.0.1 in little endian becomes this in network byte order
    // We need to test proper conversion
    EXPECT_FALSE(util::ip_to_string(0x01020304).empty());
}

TEST(ParseIpv4Test, Valid) {
    bool ok = false;
    uint32_t ip = util::parse_ipv4_be("192.168.1.1", &ok);
    EXPECT_TRUE(ok);
    EXPECT_NE(ip, 0u);
}

TEST(ParseIpv4Test, Invalid) {
    bool ok = true;
    util::parse_ipv4_be("not.an.ip.address", &ok);
    EXPECT_FALSE(ok);
}

TEST(ParseIpv4Test, Empty) {
    bool ok = true;
    util::parse_ipv4_be("", &ok);
    EXPECT_FALSE(ok);
}

TEST(JsonEscapeTest, NoEscape) {
    EXPECT_EQ(util::json_escape("hello"), "hello");
}

TEST(JsonEscapeTest, Quotes) {
    EXPECT_EQ(util::json_escape("say \"hello\""), "say \\\"hello\\\"");
}

TEST(JsonEscapeTest, Backslash) {
    EXPECT_EQ(util::json_escape("path\\to\\file"), "path\\\\to\\\\file");
}

TEST(JsonEscapeTest, Newlines) {
    EXPECT_EQ(util::json_escape("line1\nline2"), "line1\\nline2");
}

TEST(JsonEscapeTest, ControlChars) {
    std::string input = "hello\tworld";
    EXPECT_EQ(util::json_escape(input), "hello\\tworld");
}

TEST(Iso8601Test, Basic) {
    // Test that we get a valid timestamp string
    std::string ts = util::iso8601_utc(0.0); // Unix epoch
    EXPECT_FALSE(ts.empty());
    EXPECT_TRUE(ts.find("1970") != std::string::npos);
}

TEST(Iso8601Test, RecentTimestamp) {
    // Use a timestamp from 2024
    double epoch_2024 = 1704067200.0; // 2024-01-01 00:00:00 UTC
    std::string ts = util::iso8601_utc(epoch_2024);
    EXPECT_TRUE(ts.find("2024") != std::string::npos);
}

} // namespace
