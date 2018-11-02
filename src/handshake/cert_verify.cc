#include "handshake/cert_verify.h"
#include "handshake/encode.h"

namespace tun {
namespace handshake {

size_t cert_verify::serialize(std::basic_ostringstream<uint8_t>& sstr) {
    size_t ret = 0;
    size_t len = 0;

    // encode algo
    ret += uint_encode(sstr, this->_sign_algo);

    // encode sign
    len = this->_sign.size();
    ret += uint_encode(sstr, static_cast<uint16_t>(len));
    sstr.write(this->_sign.data(), this->_sign.size());
    ret += this->_sign.size();

    return ret;
}

void cert_verify::deserialize(std::basic_istringstream<uint8_t>& sstr) {
    size_t len = 0;

    // decode algo
    this->_sign_algo = uint_decode<x509::sign_algo>(sstr);

    // decode sign
    len = uint_decode<uint16_t>(sstr);
    this->_sign.resize(len);
    sstr.read(const_cast<uint8_t *>(this->_sign.data()), this->_sign.size());
}

size_t cert_verify::size() const {
    return sizeof(x509::sign_algo) + 2 + this->_sign.size();
}

}
}
