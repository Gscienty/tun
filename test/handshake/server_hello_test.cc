#include "handshake/server_hello.h"
#include "gtest/gtest.h"

TEST(server_hello, encode_1) {
    using namespace tun::handshake;

    server_hello e;

    e.version() = 0x0303;
    for (int i = 0; i < 32; i++) { e.random()[i] = i; }
    e.legacy_session_id().resize(8);
    for (int i = 0; i < 8; i++) { e.legacy_session_id()[i] = i; }
    e.cipher_suite() = 0xABCD;
    e.legacy_compression_method() = 0xEF;

    std::basic_ostringstream<uint8_t> sstr;

    e.serialize(sstr);
    auto ret = sstr.str();
    uint8_t expect[] = {
        0x03, 0x03,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        8, 0, 1, 2, 3, 4, 5, 6, 7,
        0xAB, 0xCD,
        0xEF,
        0, 0
    };
    EXPECT_EQ(ret.size(), sizeof(expect));
    for (size_t i = 0; i < sizeof(expect); i++) {
        EXPECT_EQ(ret[i], expect[i]);
    }
}

TEST(server_hello, encode_2) {
    using namespace tun::handshake;

    server_hello e;

    e.version() = 0x0303;
    for (int i = 0; i < 32; i++) { e.random()[i] = i; }
    e.legacy_session_id().resize(8);
    for (int i = 0; i < 8; i++) { e.legacy_session_id()[i] = i; }
    e.cipher_suite() = 0xABCD;
    e.legacy_compression_method() = 0xEF;

    tls_extension ext;
    ext.type() = 0x1234;
    ext.data().resize(8);
    for (int i = 0; i < 8; i++) { ext.data()[i] = i; }
    e.extensions().push_back(ext);

    std::basic_ostringstream<uint8_t> sstr;

    e.serialize(sstr);
    auto ret = sstr.str();
    uint8_t expect[] = {
        0x03, 0x03,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        8, 0, 1, 2, 3, 4, 5, 6, 7,
        0xAB, 0xCD,
        0xEF,
        0, 12,
        0x12, 0x34, 0, 8, 0, 1, 2, 3, 4, 5, 6, 7
    };
    EXPECT_EQ(ret.size(), sizeof(expect));
    for (size_t i = 0; i < sizeof(expect); i++) {
        EXPECT_EQ(ret[i], expect[i]);
    }
}

TEST(server_hello, encode_3) {
    using namespace tun::handshake;

    server_hello e;

    e.version() = 0x0303;
    for (int i = 0; i < 32; i++) { e.random()[i] = i; }
    e.legacy_session_id().resize(8);
    for (int i = 0; i < 8; i++) { e.legacy_session_id()[i] = i; }
    e.cipher_suite() = 0xABCD;
    e.legacy_compression_method() = 0xEF;

    tls_extension ext;
    ext.type() = 0x1234;
    ext.data().resize(8);
    for (int i = 0; i < 8; i++) { ext.data()[i] = i; }
    e.extensions().push_back(ext);

    tls_extension ext2;
    ext2.type() = 0x5678;
    ext2.data().resize(16);
    for (int i = 0; i < 16; i++) { ext2.data()[i] = i; }
    e.extensions().push_back(ext2);

    std::basic_ostringstream<uint8_t> sstr;

    e.serialize(sstr);
    auto ret = sstr.str();
    uint8_t expect[] = {
        0x03, 0x03,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        8, 0, 1, 2, 3, 4, 5, 6, 7,
        0xAB, 0xCD,
        0xEF,
        0, 32,
        0x12, 0x34, 0, 8, 0, 1, 2, 3, 4, 5, 6, 7,
        0x56, 0x78, 0, 16, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    };
    EXPECT_EQ(ret.size(), sizeof(expect));
    for (size_t i = 0; i < sizeof(expect); i++) {
        EXPECT_EQ(ret[i], expect[i]);
    }
}

TEST(server_hello, encode_decode) {
    using namespace tun::handshake;

    server_hello e;

    e.version() = 0x0303;
    for (int i = 0; i < 32; i++) { e.random()[i] = i; }
    e.legacy_session_id().resize(8);
    for (int i = 0; i < 8; i++) { e.legacy_session_id()[i] = i; }
    e.cipher_suite() = 0xABCD;
    e.legacy_compression_method() = 0xEF;

    std::basic_ostringstream<uint8_t> sstr;

    e.serialize(sstr);
    auto ret = sstr.str();

    std::basic_istringstream<uint8_t> isstr;
    isstr.rdbuf()->pubsetbuf(const_cast<uint8_t *>(ret.data()), ret.size());

    server_hello ex;
    ex.deserialize(isstr);

    EXPECT_EQ(e, ex);
}

TEST(server_hello, encode_decode_1) {
    using namespace tun::handshake;

    server_hello e;

    e.version() = 0x0303;
    for (int i = 0; i < 32; i++) { e.random()[i] = i; }
    e.legacy_session_id().resize(8);
    for (int i = 0; i < 8; i++) { e.legacy_session_id()[i] = i; }
    e.cipher_suite() = 0xABCD;
    e.legacy_compression_method() = 0xEF;

    tls_extension ext;
    ext.type() = 0x1234;
    ext.data().resize(8);
    for (int i = 0; i < 8; i++) { ext.data()[i] = i; }
    e.extensions().push_back(ext);

    std::basic_ostringstream<uint8_t> sstr;

    e.serialize(sstr);
    auto ret = sstr.str();

    std::basic_istringstream<uint8_t> isstr;
    isstr.rdbuf()->pubsetbuf(const_cast<uint8_t *>(ret.data()), ret.size());

    server_hello ex;
    ex.deserialize(isstr);

    EXPECT_EQ(e, ex);
}

TEST(server_hello, encode_decode_2) {
    using namespace tun::handshake;

    server_hello e;

    e.version() = 0x0303;
    for (int i = 0; i < 32; i++) { e.random()[i] = i; }
    e.legacy_session_id().resize(8);
    for (int i = 0; i < 8; i++) { e.legacy_session_id()[i] = i; }
    e.cipher_suite() = 0xABCD;
    e.legacy_compression_method() = 0xEF;

    tls_extension ext;
    ext.type() = 0x1234;
    ext.data().resize(8);
    for (int i = 0; i < 8; i++) { ext.data()[i] = i; }
    e.extensions().push_back(ext);

    tls_extension ext2;
    ext2.type() = 0x5678;
    ext2.data().resize(16);
    for (int i = 0; i < 16; i++) { ext2.data()[i] = i; }
    e.extensions().push_back(ext2);

    std::basic_ostringstream<uint8_t> sstr;

    e.serialize(sstr);
    auto ret = sstr.str();

    std::basic_istringstream<uint8_t> isstr;
    isstr.rdbuf()->pubsetbuf(const_cast<uint8_t *>(ret.data()), ret.size());

    server_hello ex;
    ex.deserialize(isstr);

    EXPECT_EQ(e, ex);
}

int main() {
    return RUN_ALL_TESTS();
}
