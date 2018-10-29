#ifndef _TUN_HANDSHAKE_TYPE_
#define _TUN_HANDSHAKE_TYPE_

#include <cstdint>

namespace tun {
namespace handshake {

typedef uint16_t protocol_version_t;
typedef uint16_t cipher_suite_t;
typedef uint16_t extension_type_t;

enum handshake_type : uint8_t {
    HT_CLIENT_HELLO         = 1,
    HT_SERVER_HELLO         = 2,
    HT_NEW_SESSION_TICKET   = 4,
    HT_END_OF_EARLY_DATA    = 5,
    HT_ENCRYPTED_EXTENSIONS = 8,
    HT_CERTIFICATE          = 11,
    HT_CERTIFICATE_REQUEST  = 13,
    HT_CERTIFICATE_VERIFY   = 15,
    HT_FINISHED             = 20,
    HT_KEY_UPDATE           = 24,
    HT_MESSAGE_HASH         = 254,
    HT_EMPTY                = 255
};

}
}

#endif
