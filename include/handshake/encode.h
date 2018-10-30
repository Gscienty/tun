#ifndef _TUN_HANDSHAKE_ENCODE_
#define _TUN_HANDSHAKE_ENCODE_

#include "handshake/entity.h"
#include <cstdint>
#include <sstream>
#include <stdexcept>
#include <memory>
#ifdef DEBUG
#include <iostream>
#endif

namespace tun {
namespace handshake {

template <typename T_Int> size_t uint_encode(std::basic_ostringstream<uint8_t>& sstr, T_Int val) {
    for (int i = 0; i < sizeof(T_Int); i++) {
        sstr.put(static_cast<uint8_t>((val >> (8 * (sizeof(T_Int) - i - 1))) & 0xFF));
    }
    return sizeof(T_Int);
}

template <typename T_Int> T_Int uint_decode(std::basic_istringstream<uint8_t>& sstr) {
    T_Int ret = 0;
    for (int i = 0; i < sizeof(T_Int); i++) {
        ret = ret << 8;
        ret |= sstr.get();
    }
    return ret;
}

size_t varint_encode(std::basic_ostringstream<uint8_t>&, uint64_t);
uint64_t varint_decode(std::basic_istringstream<uint8_t>&);

size_t entity_encode(std::basic_ostringstream<uint8_t>&, entity&);
std::unique_ptr<entity> entity_decode(std::basic_istringstream<uint8_t>&);

}
}

#endif
