#include "handshake/cert_body.h"
#include "handshake/encode.h"

namespace tun {
namespace handshake {

size_t cert_body::serialize(std::basic_ostringstream<uint8_t>& sstr) {
    size_t ret = 0;
    size_t len = 0;

    // encode ctx
    len = this->_ctx.size();
    ret += uint_encode(sstr, static_cast<uint8_t>(len));
    sstr.write(this->_ctx.data(), this->_ctx.size());
    ret += this->_ctx.size();

    // encode certs
    len = 0;
    for (auto& c : this->_certs) { len += c.size(); }
    ret += uint_encode(sstr, static_cast<uint16_t>(len >> 8));
    ret += uint_encode(sstr, static_cast<uint8_t>(len));
    for (auto& c : this->_certs) { ret += c.serialize(sstr); }

    return ret;
}

void cert_body::deserialize(std::basic_istringstream<uint8_t>& sstr) {
    size_t len = 0;

    // decode ctx
    len = uint_decode<uint8_t>(sstr);
    this->_ctx.resize(len);
    sstr.read(const_cast<uint8_t *>(this->_ctx.data()), this->_ctx.size());

    len = uint_decode<uint16_t>(sstr);
    len <<= 8;
    len |= uint_decode<uint8_t>(sstr);
    this->_certs.clear();
    while (len > 0) {
        cert_entity ent;
        ent.entity::deserialize(sstr);
        this->_certs.push_back(ent);

        len -= ent.size();
    }
}

}
}
