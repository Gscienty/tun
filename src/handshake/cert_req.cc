#include "handshake/cert_req.h"
#include "handshake/encode.h"

namespace tun {
namespace handshake {

size_t cert_req::serialize(std::basic_ostringstream<uint8_t>& sstr) {
    size_t ret = 0;
    size_t len = 0;

    // encode ctx
    len = this->_ctx.size();
    ret += uint_encode(sstr, static_cast<uint8_t>(len));

    // encode extensions
    len = 0;
    for (auto& c : this->_extensions) { len += c.size(); }
    ret += uint_encode(sstr, static_cast<uint16_t>(len));
    for (auto& c : this->_extensions) { ret += c.serialize(sstr); }

    return ret;
}

void cert_req::deserialize(std::basic_istringstream<uint8_t>& sstr) {
    size_t len = 0;

    // decode ctx
    len = uint_decode<uint8_t>(sstr);
    this->_ctx.resize(len);
    sstr.read(const_cast<uint8_t *>(this->_ctx.data()), this->_ctx.size());

    // decode extensions
    this->_extensions.clear();
    len = uint_decode<uint16_t>(sstr);
    while (len > 0) {
        tls_extension ext;
        ext.deserialize(sstr);
        this->_extensions.push_back(ext);

        len -= ext.size();
    }
}

size_t cert_req::size() const {
    size_t ret = 1 + this->_ctx.size() + 2;
    for (auto& c : this->_extensions) { ret += c.size(); }
    return ret;
}

}
}
