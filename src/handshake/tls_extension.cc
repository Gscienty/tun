#include "handshake/tls_extension.h"
#include "handshake/encode.h"

namespace tun {
namespace handshake {

size_t tls_extension::serialize(std::basic_ostringstream<uint8_t>& sstr) {
    size_t ret = 0;

    // encode type
    ret += uint_encode(sstr, this->_type);

    // encode data
    size_t arr_len = this->_data.size();
    ret += uint_encode(sstr, static_cast<uint16_t>(arr_len));
    for (auto c : this->_data) { ret += uint_encode(sstr, c); }

    return ret;
}

void tls_extension::deserialize(std::basic_istringstream<uint8_t>& sstr) {
    this->_type = uint_decode<extension_type_t>(sstr);
    size_t len = uint_decode<uint16_t>(sstr);
    this->_data.resize(len);
    for (auto& c : this->_data) { c = uint_decode<uint8_t>(sstr); }
}

size_t tls_extension::size() const {
    return sizeof(extension_type_t) + 2 + this->_data.size();
}

bool tls_extension::operator==(const tls_extension& other) const {
    if (this->_type != other._type) {
        return false;
    }
    if (this->_data.size() != other._data.size()) {
        return false;
    }
    size_t len = this->_data.size();
    for (size_t i = 0; i < len; i++) {
        if (this->_data[i] != other._data[i]) {
            return false;
        }
    }
    return true;
}

bool tls_extension::operator!=(const tls_extension& other) const {
    return !(*this == other);
}

}
}
