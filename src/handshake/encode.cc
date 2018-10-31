#include "handshake/encode.h"
#include "handshake/client_hello.h"
#include "handshake/server_hello.h"
#include "handshake/new_session_ticket.h"
#include "handshake/encrypted_extensions.h"
#include "handshake/end_of_early_data.h"
#include "handshake/finished.h"
#include "handshake/key_update_request.h"

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

size_t entity_encode(std::basic_ostringstream<uint8_t>& sstr, entity& e) {
    uint_encode(sstr, e.type());
    size_t len = e.size();
    uint_encode(sstr, static_cast<uint16_t>(len >> 8));
    uint_encode(sstr, static_cast<uint8_t>(len));
    e.serialize(sstr);
    return 4 + e.size();
}

std::unique_ptr<entity> entity_decode(std::basic_istringstream<uint8_t>& sstr) {
    std::unique_ptr<entity> ptr;
    handshake_type type = uint_decode<handshake_type>(sstr);

    size_t len = 0;
    len = uint_decode<uint16_t>(sstr);
    len <<= 8;
    len |= uint_decode<uint8_t>(sstr);

    if (len < static_cast<size_t>(sstr.rdbuf()->in_avail())) {
        return ptr;
    }

    switch (type) {
    case HT_CLIENT_HELLO:
        ptr.reset(new client_hello());
        break;
    case HT_SERVER_HELLO:
        ptr.reset(new server_hello());
        break;
    case HT_NEW_SESSION_TICKET:
        ptr.reset(new new_session_ticket());
        break;
    case HT_ENCRYPTED_EXTENSIONS:
        ptr.reset(new encrypted_extensions());
        break;
    case HT_END_OF_EARLY_DATA:
        ptr.reset(new end_of_early_data());
        break;
    case HT_FINISHED:
        ptr.reset(new finished());
        break;
    case HT_KEY_UPDATE:
        ptr.reset(new key_update_request());
        break;
    default:
        break;
    }

    if (bool(ptr)) {
        ptr->deserialize(sstr);
    }

    return ptr;
}

}
}
