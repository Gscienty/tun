#include "handshake/finished.h"

namespace tun {
namespace handshake {

size_t finished::serialize(std::basic_ostringstream<uint8_t>& sstr) {
    // encode data
    sstr.write(this->_data.data(), this->_data.size());
    return this->_len;
}

void finished::deserialize(std::basic_istringstream<uint8_t>& sstr) {
    // decode data
    this->_data.resize(this->_len);
    sstr.read(const_cast<uint8_t *>(this->_data.data()), this->_data.size());
}

size_t finished::size() const {
    return this->_len;
}

}
}
