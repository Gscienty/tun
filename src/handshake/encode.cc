#include "handshake/encode.h"

namespace tun {
namespace handshake {


size_t varint_encode(std::basic_ostringstream<uint8_t>& sstr, uint64_t val) {
    int len_pt = 0;    
    for (; len_pt < 4; len_pt++) {
        if (val < (1UL << (8 * (1 << len_pt) - 2))) {
            break;
        }
    }

    if (len_pt == 4) {
        throw std::out_of_range("varint out of maximum");
    }

    val |= static_cast<uint64_t>(len_pt) << (8 * (1 << len_pt) - 2);
    switch (len_pt) {
    case 0:
        return uint_encode(sstr, static_cast<uint8_t>(val));
    case 1:
        return uint_encode(sstr, static_cast<uint16_t>(val));
    case 2:
        return uint_encode(sstr, static_cast<uint32_t>(val));
    case 3:
        return uint_encode(sstr, static_cast<uint64_t>(val));
    default:
        throw std::bad_exception();
    }
}

uint64_t varint_decode(std::basic_istringstream<uint8_t>& sstr) {
    uint8_t first_byte = sstr.peek();
    uint8_t pt = (first_byte & 0xC0) >> 6;
    switch (pt) {
    case 0:
        return uint_decode<uint8_t>(sstr);
    case 1:
        return uint_decode<uint16_t>(sstr) & 0x3FFF;
    case 2:
        return uint_decode<uint32_t>(sstr) & 0x3FFFFFFF;
    case 3:
        return uint_decode<uint64_t>(sstr) & 0x3FFFFFFFFFFFFFFF;
    default:
        throw std::bad_exception();
    }
}

}
}
