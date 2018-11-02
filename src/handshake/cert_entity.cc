#include "handshake/cert_entity.h"
#include "handshake/encode.h"

namespace tun {
namespace handshake {

size_t cert_entity::serialize(std::basic_ostringstream<uint8_t>& sstr) {
    size_t ret = 0;
    size_t len = 0;

    // encode data
    len = this->_data.size();
    ret += uint_encode(sstr, static_cast<uint16_t>(len >> 8));
    ret += uint_encode(sstr, static_cast<uint8_t>(len));
    sstr.write(this->_data.data(), this->_data.size());
    ret += this->_data.size();

    // encode extensions
    len = 0;
    for (auto& c : this->_extensions) { len += c.size(); }
    uint_encode(sstr, static_cast<uint16_t>(len));
    for (auto& c : this->_extensions) { ret += c.serialize(sstr); }

    return ret;
}

void cert_entity::deserialize(std::basic_istringstream<uint8_t>& sstr) {
    size_t len = 0;

    // decode data
    len = uint_decode<uint16_t>(sstr);
    len <<= 8;
    len |= uint_decode<uint8_t>(sstr);
    this->_data.resize(len);
    sstr.read(const_cast<uint8_t *>(this->_data.data()), this->_data.size());

    // decode extension
    this->_extensions.clear();
    len = uint_decode<uint16_t>(sstr);
    while (len > 0) {
        tls_extension ext;
        ext.deserialize(sstr);
        this->_extensions.push_back(ext);

        len -= ext.size();
    }
}

size_t cert_entity::size() const {
    size_t ret = 3 + this->_data.size() + 2;
    for (auto& c : this->_extensions) { ret += c.size(); }
    return ret;
}

}
}
