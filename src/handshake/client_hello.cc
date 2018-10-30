#include "handshake/client_hello.h"
#include "handshake/encode.h"
#include <sstream>
#include <stdexcept>
#include <random>

namespace tun {
namespace handshake {

client_hello::client_hello() {
    this->_random.resize(32, 0);
    for (auto& c : this->_random) { c = std::rand(); }
}

size_t client_hello::serialize(std::basic_ostringstream<uint8_t>& sstr) {
    size_t arr_len = 0;
    size_t ret = 0;
    
    // encode legacy version
    ret += uint_encode(sstr, this->_legacy_version);

    // encode random
    if (this->_random.size() != 32) {
        throw std::bad_exception();
    }
    for (auto c : this->_random) { ret += uint_encode(sstr, c); }
    
    // encode legacy session id
    arr_len = this->_legacy_session_id.size();
    if (arr_len > 32) {
        throw std::out_of_range("legacy session id out of range");
    }
    ret += uint_encode(sstr, static_cast<uint8_t>(arr_len));
    for (auto c : this->_legacy_session_id) { ret += uint_encode(sstr, c); }

    // encode cipher suites
    arr_len = this->_cipher_suites.size();
    if (arr_len * 2 < 1) {
        throw std::bad_exception();
    }
    ret += uint_encode(sstr, static_cast<uint16_t>(arr_len * 2));
    for (auto c : this->_cipher_suites) { ret += uint_encode(sstr, c); }

    // encode legacy compression methods
    arr_len = this->_legacy_compression_methods.size();
    if (arr_len < 1) {
        throw std::bad_exception();
    }
    ret += uint_encode(sstr, static_cast<uint8_t>(arr_len));
    for (auto c : this->_legacy_compression_methods) { ret += uint_encode(sstr, c); }

    // encode extension
    arr_len = 0;
    for (auto c : this->_extensions) { arr_len += c.size(); }
    ret += uint_encode(sstr, static_cast<uint16_t>(arr_len));
    for (auto c : this->_extensions) { ret += c.serialize(sstr); }

    return ret;
}

void client_hello::deserialize(std::basic_istringstream<uint8_t>& sstr) {
    int len = 0;
    // decode legacy version
    this->_legacy_version = uint_decode<protocol_version_t>(sstr);

    // decode random
    this->_random.resize(32, 0);
    for (auto& c : this->_random) { c = uint_decode<uint8_t>(sstr); }

    // decode legacy session id
    len = uint_decode<uint8_t>(sstr);
    this->_legacy_session_id.resize(len);
    for (auto& c : this->_legacy_session_id) { c = uint_decode<uint8_t>(sstr); }

    // decode cipher suites
    len = uint_decode<uint16_t>(sstr);
    this->_cipher_suites.resize(len / 2);
    for (auto& c : this->_cipher_suites) { c = uint_decode<cipher_suite_t>(sstr); }

    // decode legacy compression methods
    len = uint_decode<uint8_t>(sstr);
    this->_legacy_compression_methods.resize(len);
    for (auto& c : this->_legacy_compression_methods) { c = uint_decode<uint8_t>(sstr); }

    // decode extension
    this->_extensions.clear();
    len = uint_decode<uint16_t>(sstr);
    while (len > 0) {
        tls_extension ext;
        ext.deserialize(sstr);
        len -= ext.size();

        this->_extensions.push_back(ext);
    }
}

size_t client_hello::size() const {
    size_t ret = sizeof(protocol_version_t) + 
        32 +
        1 + this->_legacy_session_id.size() +
        2 + this->_cipher_suites.size() * sizeof(cipher_suite_t) +
        1 + this->_legacy_compression_methods.size() +
        2;

    for (auto& c : this->_extensions) { ret += c.size(); }

    return ret;
}

bool client_hello::operator==(const client_hello& other) const {
    size_t len = 0;
    if (this->_legacy_version != other._legacy_version) {
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

    if (this->_cipher_suites.size() != other._cipher_suites.size()) {
        return false;
    }
    len = this->_cipher_suites.size();
    for (size_t i = 0; i < len; i++) {
        if (this->_cipher_suites[i] != other._cipher_suites[i]) {
            return false;
        }
    }

    if (this->_legacy_compression_methods.size() != other._legacy_compression_methods.size()) {
        return false;
    }
    len = this->_legacy_compression_methods.size();
    for (size_t i = 0; i < len; i++) {
        if (this->_legacy_compression_methods[i] != other._legacy_compression_methods[i]) {
            return false;
        }
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

bool client_hello::operator!= (const client_hello& other) const {
    return !(*this == other);
}

}
}
