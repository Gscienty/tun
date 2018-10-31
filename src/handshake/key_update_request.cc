#include "handshake/key_update_request.h"
#include "handshake/encode.h"

namespace tun {
namespace handshake {

size_t key_update_request::serialize(std::basic_ostringstream<uint8_t>& sstr) {
    // encode key update request
    uint_encode(sstr, this->_key_update_request);
    return 1;
}

void key_update_request::deserialize(std::basic_istringstream<uint8_t>& sstr) {
    // decode key update request
    this->_key_update_request = uint_decode<key_update_request_t>(sstr);
}

size_t key_update_request::size() const {
    return 1;
}

}
}
