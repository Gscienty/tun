#ifndef _TUN_HANDSHAKE_ENTITY_
#define _TUN_HANDSHAKE_ENTITY_

#include "handshake/type.h"
#include <cstdint>
#include <sstream>

namespace tun {
namespace handshake {

class entity {
public:
    virtual handshake_type type() const = 0;
    virtual size_t serialize(std::basic_ostringstream<uint8_t>&) = 0;
    virtual void deserialize(std::basic_istringstream<uint8_t>&) = 0;
    virtual size_t size() const = 0;
};

}
}

#endif
