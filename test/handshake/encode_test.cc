#include "handshake/encode.h"
#include "gtest/gtest.h"

TEST(uint_encode, uint8) {
    using namespace tun::handshake;
    std::basic_ostringstream<uint8_t> sstr;
    uint_encode(sstr, static_cast<uint8_t>(0xFC));

    auto ret = sstr.str();

    EXPECT_EQ(0xFC, ret[0]);
}

TEST(uint_encode, uint16) {
    using namespace tun::handshake;
    std::basic_ostringstream<uint8_t> sstr;
    uint_encode(sstr, static_cast<uint16_t>(0xFCAB));

    auto ret = sstr.str();

    EXPECT_EQ(2, ret.size());

    EXPECT_EQ(0xFC, ret[0]);
    EXPECT_EQ(0xAB, ret[1]);
}

TEST(uint_encode, uint32) {
    using namespace tun::handshake;
    std::basic_ostringstream<uint8_t> sstr;
    uint_encode(sstr, static_cast<uint32_t>(0xFCAB1234));

    auto ret = sstr.str();

    EXPECT_EQ(4, ret.size());

    EXPECT_EQ(0xFC, ret[0]);
    EXPECT_EQ(0xAB, ret[1]);
    EXPECT_EQ(0x12, ret[2]);
    EXPECT_EQ(0x34, ret[3]);
}

TEST(uint_encode, uint64) {
    using namespace tun::handshake;
    std::basic_ostringstream<uint8_t> sstr;
    
    uint_encode(sstr, 0xFCAB12345678DE32);

    auto ret = sstr.str();

    EXPECT_EQ(8, ret.size());

    EXPECT_EQ(0xFC, ret[0]);
    EXPECT_EQ(0xAB, ret[1]);
    EXPECT_EQ(0x12, ret[2]);
    EXPECT_EQ(0x34, ret[3]);
    EXPECT_EQ(0x56, ret[4]);
    EXPECT_EQ(0x78, ret[5]);
    EXPECT_EQ(0xDE, ret[6]);
    EXPECT_EQ(0x32, ret[7]);
}

TEST(varint_encode, uint8) {
    using namespace tun::handshake;
    std::basic_ostringstream<uint8_t> sstr;
    
    varint_encode(sstr, 0x23);

    auto ret = sstr.str();
    EXPECT_EQ(1, ret.size());
    EXPECT_EQ(0x23, ret[0]);
}

TEST(varint_encode, uint8_2) {
    using namespace tun::handshake;
    std::basic_ostringstream<uint8_t> sstr;

    varint_encode(sstr, 0xFF);
    
    auto ret = sstr.str();
    EXPECT_EQ(2, ret.size());
    EXPECT_EQ(0x40, ret[0]);
    EXPECT_EQ(0xFF, ret[1]);
}

TEST(varint_encode, uint16) {
    using namespace tun::handshake;
    std::basic_ostringstream<uint8_t> sstr;

    varint_encode(sstr, 0x1234);

    auto ret = sstr.str();
    EXPECT_EQ(2, ret.size());
    EXPECT_EQ(0x52, ret[0]);
    EXPECT_EQ(0x34, ret[1]);
}

TEST(varint_encode, uint16_2) {
    using namespace tun::handshake;
    std::basic_ostringstream<uint8_t> sstr;

    varint_encode(sstr, 0x5678);

    auto ret = sstr.str();
    EXPECT_EQ(4, ret.size());
    EXPECT_EQ(0x80, ret[0]);
    EXPECT_EQ(0x00, ret[1]);
    EXPECT_EQ(0x56, ret[2]);
    EXPECT_EQ(0x78, ret[3]);
}

TEST(varint_encode, uint32) {
    using namespace tun::handshake;
    std::basic_ostringstream<uint8_t> sstr;

    varint_encode(sstr, 0x12345678);

    auto ret = sstr.str();
    EXPECT_EQ(4, ret.size());
    EXPECT_EQ(0x92, ret[0]);
    EXPECT_EQ(0x34, ret[1]);
    EXPECT_EQ(0x56, ret[2]);
    EXPECT_EQ(0x78, ret[3]);
}

TEST(varint_encode, uint32_2) {
    using namespace tun::handshake;
    std::basic_ostringstream<uint8_t> sstr;

    varint_encode(sstr, 0xFF123456);
    auto ret = sstr.str();
    EXPECT_EQ(8, ret.size());
    EXPECT_EQ(0xC0, ret[0]);
    EXPECT_EQ(0x00, ret[1]);
    EXPECT_EQ(0x00, ret[2]);
    EXPECT_EQ(0x00, ret[3]);
    EXPECT_EQ(0xFF, ret[4]);
    EXPECT_EQ(0x12, ret[5]);
    EXPECT_EQ(0x34, ret[6]);
    EXPECT_EQ(0x56, ret[7]);
}

TEST(varint_encode, uint64) {
    using namespace tun::handshake;
    std::basic_ostringstream<uint8_t> sstr;

    varint_encode(sstr, 0x1122334455667788);
    auto ret = sstr.str();
    EXPECT_EQ(8, ret.size());
    EXPECT_EQ(0xD1, ret[0]);
    EXPECT_EQ(0x22, ret[1]);
    EXPECT_EQ(0x33, ret[2]);
    EXPECT_EQ(0x44, ret[3]);
    EXPECT_EQ(0x55, ret[4]);
    EXPECT_EQ(0x66, ret[5]);
    EXPECT_EQ(0x77, ret[6]);
    EXPECT_EQ(0x88, ret[7]);
}

TEST(varint_encode, uint64_2) {
    using namespace tun::handshake;
    std::basic_ostringstream<uint8_t> sstr;

    try {
        varint_encode(sstr, 0xFFFFFFFFFFFFFFFF);
        FAIL();
    }
    catch (std::out_of_range ex) {
        SUCCEED();
    }
}

int main() {
    return RUN_ALL_TESTS();
}
