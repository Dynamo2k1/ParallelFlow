// Unit tests for Space-Saving heavy hitter algorithm

#include <gtest/gtest.h>
#include "space_saving.h"
#include <string>

namespace {

TEST(SpaceSavingTest, EmptyCapacity) {
    SpaceSaving<uint32_t, uint64_t> ss(0);
    ss.add(12345, 100);
    auto top = ss.top();
    EXPECT_TRUE(top.empty());
}

TEST(SpaceSavingTest, SingleItem) {
    SpaceSaving<uint32_t, uint64_t> ss(10);
    ss.add(12345, 100);
    
    auto top = ss.top();
    EXPECT_EQ(top.size(), 1u);
    EXPECT_EQ(top[0].key, 12345u);
    EXPECT_EQ(top[0].count, 100u);
}

TEST(SpaceSavingTest, MultipleItems) {
    SpaceSaving<uint32_t, uint64_t> ss(10);
    ss.add(1, 100);
    ss.add(2, 200);
    ss.add(3, 50);
    
    auto top = ss.top();
    EXPECT_EQ(top.size(), 3u);
    
    // Items should be sorted by count descending
    EXPECT_EQ(top[0].key, 2u);
    EXPECT_EQ(top[0].count, 200u);
}

TEST(SpaceSavingTest, AccumulateCount) {
    SpaceSaving<uint32_t, uint64_t> ss(10);
    ss.add(1, 100);
    ss.add(1, 50);
    ss.add(1, 25);
    
    auto top = ss.top();
    EXPECT_EQ(top.size(), 1u);
    EXPECT_EQ(top[0].count, 175u);
}

TEST(SpaceSavingTest, CapacityLimit) {
    SpaceSaving<uint32_t, uint64_t> ss(3);
    
    // Add 5 items
    for (uint32_t i = 1; i <= 5; i++) {
        ss.add(i, i * 100);
    }
    
    auto top = ss.top();
    EXPECT_LE(top.size(), 3u);
}

TEST(SpaceSavingTest, StringKeys) {
    SpaceSaving<std::string, uint64_t> ss(10);
    ss.add("google.com", 1000);
    ss.add("facebook.com", 500);
    ss.add("amazon.com", 750);
    
    auto top = ss.top();
    EXPECT_EQ(top.size(), 3u);
    EXPECT_EQ(top[0].key, "google.com");
}

TEST(SpaceSavingTest, LargeStream) {
    SpaceSaving<uint32_t, uint64_t> ss(10);
    
    // Simulate Zipfian distribution
    for (int i = 0; i < 1000; i++) {
        ss.add(1, 100);  // Most frequent
    }
    for (int i = 0; i < 500; i++) {
        ss.add(2, 50);
    }
    for (int i = 0; i < 100; i++) {
        ss.add(3, 10);
    }
    
    auto top = ss.top();
    EXPECT_EQ(top[0].key, 1u);
    EXPECT_GT(top[0].count, top[1].count);
}

TEST(SpaceSavingTest, ZeroCapacityNoOp) {
    SpaceSaving<std::string, uint64_t> ss(0);
    ss.add("test", 100);
    EXPECT_TRUE(ss.top().empty());
    EXPECT_EQ(ss.capacity(), 0u);
}

TEST(SpaceSavingTest, SetCapacity) {
    SpaceSaving<uint32_t, uint64_t> ss(10);
    EXPECT_EQ(ss.capacity(), 10u);
    
    ss.set_capacity(5);
    EXPECT_EQ(ss.capacity(), 5u);
}

} // namespace
