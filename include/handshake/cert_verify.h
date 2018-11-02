#ifndef _TUN_HANDSHAKE_CERT_VERIFY_
#define _TUN_HANDSHAKE_CERT_VERIFY_

#include "handshake/entity.h"
#include "handshake/type.h"
#include "x509/type.h"
#include <string>
#include <cstdint>

namespace tun {
namespace handshake {

class cert_verify : entity {
private:
    x509::sign_algo _sign_algo;
    std::basic_string<uint8_t> _sign;
public:
    virtual handshake_type type() const override { return HT_CERTIFICATE_VERIFY; }
    virtual size_t serialize(std::basic_ostringstream<uint8_t>&) override;
    virtual void deserialize(std::basic_istringstream<uint8_t>&) override;
    virtual size_t size() const override;
};

}
}

#endif
