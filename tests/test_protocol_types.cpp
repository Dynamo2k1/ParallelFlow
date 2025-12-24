// Unit tests for protocol type definitions

#include <gtest/gtest.h>
#include "protocol_types.h"
#include <unordered_set>

namespace {

TEST(L4ProtoTest, Values) {
    EXPECT_EQ(static_cast<uint8_t>(L4Proto::TCP), 6);
    EXPECT_EQ(static_cast<uint8_t>(L4Proto::UDP), 17);
    EXPECT_EQ(static_cast<uint8_t>(L4Proto::ICMP), 1);
    EXPECT_EQ(static_cast<uint8_t>(L4Proto::ICMPV6), 58);
    EXPECT_EQ(static_cast<uint8_t>(L4Proto::OTHER), 0);
}

TEST(AlertTypeTest, StringConversion) {
    EXPECT_STREQ(alert_type_str(AlertType::BlocklistedIP), "blocklisted_ip");
    EXPECT_STREQ(alert_type_str(AlertType::BlocklistedDomain), "blocklisted_domain");
    EXPECT_STREQ(alert_type_str(AlertType::KeywordMatch), "keyword_match");
    EXPECT_STREQ(alert_type_str(AlertType::PortScan), "port_scan");
    EXPECT_STREQ(alert_type_str(AlertType::DNSTunnel), "dns_tunnel");
    EXPECT_STREQ(alert_type_str(AlertType::Beaconing), "beaconing");
    EXPECT_STREQ(alert_type_str(AlertType::Exfiltration), "exfiltration");
    EXPECT_STREQ(alert_type_str(AlertType::SensitiveData), "sensitive_data");
}

TEST(FlowKeyTest, EqualityIPv4) {
    FlowKey a, b;
    a.is_ipv6 = false;
    a.src_ip4 = 0x0100007F;  // 127.0.0.1
    a.dst_ip4 = 0x0200007F;  // 127.0.0.2
    a.src_port = 12345;
    a.dst_port = 80;
    a.proto = 6;  // TCP
    
    b = a;
    EXPECT_TRUE(a == b);
    
    b.dst_port = 443;
    EXPECT_FALSE(a == b);
}

TEST(FlowKeyTest, EqualityIPv6) {
    FlowKey a, b;
    a.is_ipv6 = true;
    a.src_ip6 = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    a.dst_ip6 = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    a.src_port = 12345;
    a.dst_port = 443;
    a.proto = 6;
    
    b = a;
    EXPECT_TRUE(a == b);
    
    b.src_ip6[15] = 3;
    EXPECT_FALSE(a == b);
}

TEST(FlowKeyHashTest, HashDiffers) {
    FlowKey a, b;
    FlowKeyHash hasher;
    
    a.is_ipv6 = false;
    a.src_ip4 = 0x0100007F;
    a.dst_ip4 = 0x0200007F;
    a.src_port = 12345;
    a.dst_port = 80;
    a.proto = 6;
    
    b = a;
    b.dst_port = 443;
    
    EXPECT_NE(hasher(a), hasher(b));
}

TEST(FlowKeyHashTest, HashInUnorderedSet) {
    std::unordered_set<FlowKey, FlowKeyHash> flows;
    
    FlowKey a;
    a.is_ipv6 = false;
    a.src_ip4 = 0x0100007F;
    a.dst_ip4 = 0x0200007F;
    a.src_port = 12345;
    a.dst_port = 80;
    a.proto = 6;
    
    flows.insert(a);
    flows.insert(a);  // Duplicate
    
    EXPECT_EQ(flows.size(), 1u);
}

TEST(ExtPacketViewTest, DefaultValues) {
    ExtPacketView pv;
    
    EXPECT_EQ(pv.ts_epoch, 0.0);
    EXPECT_FALSE(pv.is_ipv4);
    EXPECT_FALSE(pv.is_ipv6);
    EXPECT_FALSE(pv.is_arp);
    EXPECT_FALSE(pv.is_http);
    EXPECT_FALSE(pv.is_tls);
    EXPECT_FALSE(pv.is_dns);
    EXPECT_FALSE(pv.is_dhcp);
    EXPECT_EQ(pv.l4, L4Proto::OTHER);
    EXPECT_EQ(pv.payload, nullptr);
    EXPECT_EQ(pv.payload_len, 0u);
}

TEST(FlowStatsTest, DefaultValues) {
    FlowStats fs;
    
    EXPECT_EQ(fs.first_ts, 0.0);
    EXPECT_EQ(fs.last_ts, 0.0);
    EXPECT_EQ(fs.packets, 0u);
    EXPECT_EQ(fs.bytes, 0u);
    EXPECT_TRUE(fs.app_proto.empty());
}

TEST(CarvedFileTest, DefaultValues) {
    CarvedFile cf;
    
    EXPECT_TRUE(cf.filename.empty());
    EXPECT_TRUE(cf.sha256.empty());
    EXPECT_TRUE(cf.content_type.empty());
    EXPECT_EQ(cf.size, 0u);
    EXPECT_EQ(cf.ts, 0.0);
}

} // namespace
