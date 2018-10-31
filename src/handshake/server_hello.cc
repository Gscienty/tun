#include "handshake/server_hello.h"
#include "handshake/encode.h"
#include <random>

namespace tun {
namespace handshake {

server_hello::server_hello() {
    this->_random.resize(32);
    for (auto& c : this->_random) { c = std::rand(); }
}

size_t server_hello::serialize(std::basic_ostringstream<uint8_t>& sstr) {
    size_t ret = 0;
    size_t arr_len = 0;

    // encode version
    ret += uint_encode(sstr, this->_version);

    // encode random
    sstr.write(this->_random.data(), this->_random.size());
    ret += this->_random.size();

    // encode legacy session id
    arr_len = this->_legacy_session_id.size();
    ret += uint_encode(sstr, static_cast<uint8_t>(arr_len));
    sstr.write(this->_legacy_session_id.data(), this->_legacy_session_id.size());
    ret += this->_legacy_session_id.size();

    // encode cipher suite
    ret += uint_encode(sstr, this->_cipher_suite);

    // encode legacy compression method
    ret += uint_encode(sstr, this->_legacy_compression_method);

    // encode extensions
    arr_len = 0;
    for (auto& c : this->_extensions) { arr_len += c.size(); }
    ret += uint_encode(sstr, static_cast<uint16_t>(arr_len));
    for (auto& c : this->_extensions) { ret += c.serialize(sstr); }

    return ret;
}

void server_hello::deserialize(std::basic_istringstream<uint8_t>& sstr) {
    int len = 0;

    // decode version
    this->_version = uint_decode<protocol_version_t>(sstr);

    // decode random
    this->_random.resize(32);
    sstr.read(const_cast<uint8_t *>(this->_random.data()), this->_random.size());

    // decode legacy session id
    len = uint_decode<uint8_t>(sstr);
    this->_legacy_session_id.resize(len);
    sstr.read(const_cast<uint8_t *>(this->_legacy_session_id.data()), this->_legacy_session_id.size());

    // decode cipher suite
    this->_cipher_suite = uint_decode<cipher_suite_t>(sstr);

    // decode legacy compression method
    this->_legacy_compression_method = uint_decode<uint8_t>(sstr);

    // decode extensions
    this->_extensions.clear();
    len = uint_decode<uint16_t>(sstr);
    while (len > 0) {
        tls_extension ext;
        ext.deserialize(sstr);
        len -= ext.size();

        this->_extensions.push_back(ext);
    }
}

size_t server_hello::size() const {
    size_t ret = sizeof(protocol_version_t) +
        32 +
        1 + this->_legacy_session_id.size() +
        sizeof(cipher_suite_t) +
        1 +
        2; 
    for (auto& c : this->_extensions) { ret += c.size(); }

    return ret;
}

bool server_hello::operator== (const server_hello& other) const {
    size_t len = 0;
    if (this->_version != other._version) {
        return false;
    }
    for (int i = 0; i < 32; i++) {
        if (this->_random[i] != other._random[i]) {
            return false;
        }
    }
    if (this->_legacy_session_id.size() != other._legacy_session_id.size()) {
        return false;
    }
    len = this->_legacy_session_id.size();
    for (size_t i = 0; i < len; i++) {
        if (this->_legacy_session_id[i] != other._legacy_session_id[i]) {
            return false;
        }
    }
    if (this->_cipher_suite != other._cipher_suite) {
        return false;
    }
    if (this->_legacy_compression_method != other._legacy_compression_method) {
        return false;
    }
    if (this->_extensions.size() != other._extensions.size()) {
        return false;
    }
    len = this->_extensions.size();
    for (size_t i = 0; i < len; i++) {
        if (this->_extensions[i] != other._extensions[i]) {
            return false;
        }
    }

    return true;
}

bool server_hello::operator!=(const server_hello& other) const {
    return !(*this == other);
}

}
}
