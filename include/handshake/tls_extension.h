#ifndef _TUN_HANDSHAKE_TLS_EXTENSION_
#define _TUN_HANDSHAKE_TLS_EXTENSION_

#include "handshake/type.h"
#include <string>
#include <sstream>

namespace tun {
namespace handshake {

class tls_extension {
private:
    extension_type_t _type;
    std::basic_string<uint8_t> _data;
public:
    extension_type_t& type() { return this->_type; }
    std::basic_string<uint8_t>& data() { return this->_data; }
    size_t serialize(std::basic_ostringstream<uint8_t>&);
    void deserialize(std::basic_istringstream<uint8_t>&);
    size_t size() const;

    bool operator== (const tls_extension&) const;
    bool operator!= (const tls_extension&) const;
};

}
}

#endif
