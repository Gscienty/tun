#include "handshake/new_session_ticket.h"
#include "handshake/encode.h"
#include <stdexcept>

namespace tun {
namespace handshake {

size_t new_session_ticket::serialize(std::basic_ostringstream<uint8_t>& sstr) {
    size_t ret = 0;
    size_t len = 0;

    // encode lift time
    ret += uint_encode(sstr, this->_lifetime);

    // encode age add
    ret += uint_encode(sstr, this->_age_add);

    // encode nonce
    len = this->_nonce.size();
    if (len < 1) {
        throw std::bad_exception();
    }
    ret += uint_encode(sstr, static_cast<uint8_t>(len));
    sstr.write(this->_nonce.data(), this->_nonce.size());
    ret += this->_nonce.size();

    // encode ticket
    len = this->_ticket.size();
    if (len < 1) {
        throw std::bad_exception();
    }
    ret += uint_encode(sstr, static_cast<uint16_t>(len));
    sstr.write(this->_ticket.data(), this->_ticket.size());
    ret += this->_ticket.size();

    // encode extensions
    len = 0;
    for (auto& c : this->_extensions) { len += c.size(); }
    ret += uint_encode(sstr, static_cast<uint16_t>(len));
    for (auto& c : this->_extensions) { ret += c.serialize(sstr); }

    return ret;
}

void new_session_ticket::deserialize(std::basic_istringstream<uint8_t>& sstr) {
    size_t len = 0;

    // decode life time
    this->_lifetime = uint_decode<uint32_t>(sstr);

    // decode age add
    this->_age_add = uint_decode<uint32_t>(sstr);

    // decode nonce
    len = uint_decode<uint8_t>(sstr);
    this->_nonce.resize(len);
    sstr.read(const_cast<uint8_t *>(this->_nonce.data()), this->_nonce.size());

    // decode ticket
    len = uint_decode<uint16_t>(sstr);
    this->_ticket.resize(len);
    sstr.read(const_cast<uint8_t *>(this->_ticket.data()), this->_ticket.size());

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

size_t new_session_ticket::size() const {
    size_t ret = 4 + 4 +
        1 + this->_nonce.size() +
        2 + this->_ticket.size() +
        2;

    for (auto& c : this->_extensions) { ret += c.size(); }

    return ret;
}

}
}
