#include "handshake/encrypted_extensions.h"
#include "handshake/encode.h"

namespace tun {
namespace handshake {

size_t encrypted_extensions::serialize(std::basic_ostringstream<uint8_t>& sstr) {
    size_t ret = 0;

    // encode extension
    size_t len = 0;
    for (auto c : this->_extensions) { len += c.size(); }
    ret += uint_encode(sstr, static_cast<uint16_t>(len));
    for (auto c : this->_extensions) { ret += c.serialize(sstr); }

    return ret;
}

void encrypted_extensions::deserialize(std::basic_istringstream<uint8_t>& sstr) {
    // decode extension
    this->_extensions.clear();
    int len = uint_decode<uint16_t>(sstr);
    while (len > 0) {
        tls_extension ext;
        ext.deserialize(sstr);
        this->_extensions.push_back(ext);

        len -= ext.size();
    }
}

size_t encrypted_extensions::size() const {
    size_t ret = 2;

    for (auto& c : this->_extensions) { ret += c.size(); }

    return ret;
}

}
}
