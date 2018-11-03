#ifndef _TUN_ALERT_TYPE_
#define _TUN_ALERT_TYPE_

#include <cstdint>

namespace tun {
namespace alert {

enum alert : uint8_t {
    ALERT_CLOSE_NOTIFY                      = 0,
    ALERT_UNEXPECTED_MESSAGE                = 10,
    ALERT_BAD_RECORD_MAC                    = 20,
    ALERT_DECRYPTION_FAILED                 = 21,
    ALERT_RECORD_OVERFLOW                   = 22,
    ALERT_DECOMPRESSION_FAILURE             = 30,
    ALERT_HANDSHAKE_FAILURE                 = 40,
    ALERT_BAD_CERTIFICATE                   = 42,
    ALERT_UNSUPPORTED_CERTIFICATE           = 43,
    ALERT_CERTIFICATE_REVOKED               = 44,
    ALERT_CERTIFICATE_EXPIRED               = 45,
    ALERT_CERTIFICATE_UNKNOWN               = 46,
    ALERT_ILLEGAL_PARAMETER                 = 47,
    ALERT_UNKNOWN_CA                        = 48,
    ALERT_ACCESS_DENIED                     = 49,
    ALERT_DECODE_ERROR                      = 50,
    ALERT_DECRYPT_ERROR                     = 51,
    ALERT_PROTOCOL_VERSION                  = 70,
    ALERT_INSUFFICIENT_SECURITY             = 71,
    ALERT_INTERNAL_ERROR                    = 80,
    ALERT_INAPPROPRIATE_FALLBACK            = 86,
    ALERT_USER_CANCELED                     = 90,
    ALERT_NO_RENEGOTIATION                  = 100,
    ALERT_MISSING_EXTENSION                 = 109,
    ALERT_UNSUPPORTED_EXTENSION             = 110,
    ALERT_CERTIFICATE_UNOBTAINABLE          = 111,
    ALERT_UNRECOGNIZED_NAME                 = 112,
    ALERT_BAD_CERTIFICATE_STATS_RESPONSE    = 113,
    ALERT_BAD_CERTIFICATE_HASH_VALUE        = 114,
    ALERT_UNKNOWN_PSK_IDENTITY              = 115,
    ALERT_NO_APPLICATION_PROTOCOL           = 120,
    ALERT_STATELESS_RETRY                   = 253,
    ALERT_WOULD_BLOCK                       = 254,
    ALERT_NO_ALERT                          = 255
};

}
}

#endif
