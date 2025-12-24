// Unit tests for IOC (Indicators of Compromise) matching

#include <gtest/gtest.h>
#include "ioc.h"
#include <arpa/inet.h>

namespace {

class IocTest : public ::testing::Test {
protected:
    IocLists lists;
    
    void SetUp() override {
        // Setup test IP blocklist
        lists.ip_exact_be.insert(inet_addr("10.0.0.1"));
        lists.ip_exact_be.insert(inet_addr("192.168.1.100"));
        
        // Setup test CIDR
        CidrNet cidr;
        cidr.network_be = inet_addr("172.16.0.0");
        cidr.mask_be = inet_addr("255.255.0.0");
        lists.ip_cidrs.push_back(cidr);
        
        // Setup test domain blocklist
        lists.domains_lower.insert("malware.example.com");
        lists.domains_lower.insert("evil.org");
        lists.domains_lower.insert("bad.domain.net");
    }
};

TEST_F(IocTest, IpExactMatch) {
    EXPECT_TRUE(ip_is_blocklisted(inet_addr("10.0.0.1"), lists));
    EXPECT_TRUE(ip_is_blocklisted(inet_addr("192.168.1.100"), lists));
}

TEST_F(IocTest, IpExactNoMatch) {
    EXPECT_FALSE(ip_is_blocklisted(inet_addr("10.0.0.2"), lists));
    EXPECT_FALSE(ip_is_blocklisted(inet_addr("8.8.8.8"), lists));
}

TEST_F(IocTest, IpCidrMatch) {
    EXPECT_TRUE(ip_is_blocklisted(inet_addr("172.16.0.1"), lists));
    EXPECT_TRUE(ip_is_blocklisted(inet_addr("172.16.255.255"), lists));
}

TEST_F(IocTest, IpCidrNoMatch) {
    EXPECT_FALSE(ip_is_blocklisted(inet_addr("172.17.0.1"), lists));
    EXPECT_FALSE(ip_is_blocklisted(inet_addr("172.15.0.1"), lists));
}

TEST_F(IocTest, DomainExactMatch) {
    EXPECT_TRUE(domain_is_blocklisted("malware.example.com", lists));
    EXPECT_TRUE(domain_is_blocklisted("evil.org", lists));
    EXPECT_TRUE(domain_is_blocklisted("bad.domain.net", lists));
}

TEST_F(IocTest, DomainSubdomainMatch) {
    // Subdomain matching: foo.malware.example.com should match malware.example.com
    EXPECT_TRUE(domain_is_blocklisted("foo.malware.example.com", lists));
    EXPECT_TRUE(domain_is_blocklisted("sub.evil.org", lists));
}

TEST_F(IocTest, DomainNoMatch) {
    EXPECT_FALSE(domain_is_blocklisted("google.com", lists));
    EXPECT_FALSE(domain_is_blocklisted("example.com", lists));
    EXPECT_FALSE(domain_is_blocklisted("notevil.org", lists));
}

TEST_F(IocTest, DomainCaseSensitivity) {
    // The API expects lowercase input (qname_lower parameter name)
    // Callers are responsible for lowercasing before calling
    std::string lower1 = "malware.example.com";
    std::string lower2 = "evil.org";
    
    EXPECT_TRUE(domain_is_blocklisted(lower1, lists));
    EXPECT_TRUE(domain_is_blocklisted(lower2, lists));
    
    // Upper case should NOT match since the API expects pre-lowercased input
    EXPECT_FALSE(domain_is_blocklisted("MALWARE.EXAMPLE.COM", lists));
}

TEST_F(IocTest, EmptyLists) {
    IocLists empty;
    EXPECT_FALSE(ip_is_blocklisted(inet_addr("10.0.0.1"), empty));
    EXPECT_FALSE(domain_is_blocklisted("malware.com", empty));
}

} // namespace
