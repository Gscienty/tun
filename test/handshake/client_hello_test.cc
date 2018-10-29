#include "handshake/client_hello.h"
#include "gtest/gtest.h"
#include <iostream>
#include <iomanip>

TEST(client_hello, encode_1) {
    using namespace tun::handshake;

    client_hello e;

    e.legacy_version() = 0x0303;
    for (int i = 0; i < 32; i++) { e.random()[i] = i; }
    e.legacy_session_id().resize(32);
    for (int i = 0; i < 32; i++) { e.legacy_session_id()[i] = i; }
    e.cipher_suites().resize(1);
    e.cipher_suites()[0] = 0x1234;
    e.legacy_compression_methods().resize(1);
    e.legacy_compression_methods()[0] = 0x56;

    std::basic_ostringstream<uint8_t> sstr;

    e.serialize(sstr);
    auto ret = sstr.str();

    std::cout << std::endl;
    uint8_t expect[] = {
        0x03, 0x03, 
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        32, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        0, 2, 0x12, 0x34,
        1, 0x56,
        0, 0
    };

    for (size_t i = 0; i < sizeof(expect); i++) {
        EXPECT_EQ(ret[i], expect[i]);
    }
}

TEST(client_hello, encode_2) {
    using namespace tun::handshake;

    client_hello e;

    e.legacy_version() = 0x0303;
    for (int i = 0; i < 32; i++) { e.random()[i] = i; }
    e.legacy_session_id().resize(32);
    for (int i = 0; i < 32; i++) { e.legacy_session_id()[i] = i; }
    e.cipher_suites().resize(1);
    e.cipher_suites()[0] = 0x1234;
    e.legacy_compression_methods().resize(1);
    e.legacy_compression_methods()[0] = 0x56;

    tls_extension ext;
    ext.type() = 0x5678;
    ext.data().resize(8);
    for (int i = 0; i < 8; i++) { ext.data()[i] = i; }

    e.extensions().push_back(ext);

    std::basic_ostringstream<uint8_t> sstr;

    e.serialize(sstr);
    auto ret = sstr.str();

    uint8_t expect[] = {
        0x03, 0x03, 
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        32, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        0, 2, 0x12, 0x34,
        1, 0x56,
        0, 12,
        0x56, 0x78, 0, 8, 0, 1, 2, 3, 4, 5, 6, 7
    };

    for (size_t i = 0; i < sizeof(expect); i++) {
        EXPECT_EQ(ret[i], expect[i]);
    }
}


TEST(client_hello, encode_3) {
    using namespace tun::handshake;

    client_hello e;

    e.legacy_version() = 0x0303;
    for (int i = 0; i < 32; i++) { e.random()[i] = i; }
    e.legacy_session_id().resize(32);
    for (int i = 0; i < 32; i++) { e.legacy_session_id()[i] = i; }
    e.cipher_suites().resize(1);
    e.cipher_suites()[0] = 0x1234;
    e.legacy_compression_methods().resize(1);
    e.legacy_compression_methods()[0] = 0x56;

    tls_extension ext;
    ext.type() = 0x5678;
    ext.data().resize(8);
    for (int i = 0; i < 8; i++) { ext.data()[i] = i; }
    e.extensions().push_back(ext);

    tls_extension ext1;
    ext1.type() = 0xABCD;
    ext1.data().resize(16);
    for (int i = 0; i < 16; i++) { ext1.data()[i] = i; }
    e.extensions().push_back(ext1);

    std::basic_ostringstream<uint8_t> sstr;

    e.serialize(sstr);
    auto ret = sstr.str();

    uint8_t expect[] = {
        0x03, 0x03, 
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        32, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        0, 2, 0x12, 0x34,
        1, 0x56,
        0, 32,
        0x56, 0x78, 0, 8, 0, 1, 2, 3, 4, 5, 6, 7,
        0xAB, 0xCD, 0, 16, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    };

    for (size_t i = 0; i < sizeof(expect); i++) {
        EXPECT_EQ(ret[i], expect[i]);
    }
}

TEST(client_hello, encode_decode) {
    using namespace tun::handshake;

    client_hello e;

    e.legacy_version() = 0x0303;
    for (int i = 0; i < 32; i++) { e.random()[i] = i; }
    e.legacy_session_id().resize(32);
    for (int i = 0; i < 32; i++) { e.legacy_session_id()[i] = i; }
    e.cipher_suites().resize(1);
    e.cipher_suites()[0] = 0x1234;
    e.legacy_compression_methods().resize(1);
    e.legacy_compression_methods()[0] = 0x56;

    std::basic_ostringstream<uint8_t> sstr;

    e.serialize(sstr);
    auto ret = sstr.str();

    std::basic_istringstream<uint8_t> isstr;
    isstr.rdbuf()->pubsetbuf(const_cast<uint8_t *>(ret.data()), ret.size());

    client_hello de;
    de.deserialize(isstr);

    EXPECT_EQ(e, de);
}

TEST(client_hello, encode_decode_1) {
    using namespace tun::handshake;

    client_hello e;

    e.legacy_version() = 0x0303;
    for (int i = 0; i < 32; i++) { e.random()[i] = i; }
    e.legacy_session_id().resize(32);
    for (int i = 0; i < 32; i++) { e.legacy_session_id()[i] = i; }
    e.cipher_suites().resize(1);
    e.cipher_suites()[0] = 0x1234;
    e.legacy_compression_methods().resize(1);
    e.legacy_compression_methods()[0] = 0x56;

    tls_extension ext;
    ext.type() = 0x5678;
    ext.data().resize(8);
    for (int i = 0; i < 8; i++) { ext.data()[i] = i; }

    e.extensions().push_back(ext);

    std::basic_ostringstream<uint8_t> sstr;

    e.serialize(sstr);
    auto ret = sstr.str();

    std::basic_istringstream<uint8_t> isstr;
    isstr.rdbuf()->pubsetbuf(const_cast<uint8_t *>(ret.data()), ret.size());

    client_hello de;
    de.deserialize(isstr);

    EXPECT_EQ(e, de);
}

TEST(client_hello, encode_decode_2) {
    using namespace tun::handshake;

    client_hello e;

    e.legacy_version() = 0x0303;
    for (int i = 0; i < 32; i++) { e.random()[i] = i; }
    e.legacy_session_id().resize(32);
    for (int i = 0; i < 32; i++) { e.legacy_session_id()[i] = i; }
    e.cipher_suites().resize(1);
    e.cipher_suites()[0] = 0x1234;
    e.legacy_compression_methods().resize(1);
    e.legacy_compression_methods()[0] = 0x56;

    tls_extension ext;
    ext.type() = 0x5678;
    ext.data().resize(8);
    for (int i = 0; i < 8; i++) { ext.data()[i] = i; }
    e.extensions().push_back(ext);

    tls_extension ext1;
    ext1.type() = 0xABCD;
    ext1.data().resize(16);
    for (int i = 0; i < 16; i++) { ext1.data()[i] = i; }
    e.extensions().push_back(ext1);

    std::basic_ostringstream<uint8_t> sstr;

    e.serialize(sstr);
    auto ret = sstr.str();

    std::basic_istringstream<uint8_t> isstr;
    isstr.rdbuf()->pubsetbuf(const_cast<uint8_t *>(ret.data()), ret.size());

    client_hello de;
    de.deserialize(isstr);

    EXPECT_EQ(e, de);
}

int main() {
    return RUN_ALL_TESTS();
}
