#ifndef _TUN_FRAMING_
#define _TUN_FRAMING_

#include <cstdint>
#include <string>

namespace tun {

class framing {
public:
    virtual std::size_t header_size() const = 0;
    virtual std::size_t payload_size(std::basic_string<uint8_t>&) const = 0;

};

}

#endif
