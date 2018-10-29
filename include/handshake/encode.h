#pragma once

#include <cstdint>
#include <sstream>
#include <stdexcept>
#ifdef DEBUG
#include <iostream>
#endif

namespace tun {
namespace handshake {

template <typename T_Int> void uint_encode(std::basic_stringstream<uint8_t>& sstr, T_Int val) {
    for (int i = 0; i < sizeof(T_Int); i++) {
        sstr.put(static_cast<uint8_t>((val >> (8 * (sizeof(T_Int) - i - 1))) & 0xFF));
    }
}

void varint_encode(std::basic_stringstream<uint8_t>& sstr, uint64_t val) {
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
        uint_encode(sstr, static_cast<uint8_t>(val));
        break;
    case 1:
        uint_encode(sstr, static_cast<uint16_t>(val));
        break;
    case 2:
        uint_encode(sstr, static_cast<uint32_t>(val));
        break;
    case 3:
        uint_encode(sstr, static_cast<uint64_t>(val));
        break;
    default:
        break;
    }
};

}
}
