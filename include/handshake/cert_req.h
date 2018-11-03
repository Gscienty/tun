#ifndef _TUN_HANDSHAKE_CERT_REQ_
#define _TUN_HANDSHAKE_CERT_REQ_

#include "handshake/entity.h"
#include "handshake/tls_extension.h"
#include <vector>
#include <string>

namespace tun {
namespace handshake {

class cert_req : public entity {
private:
    std::basic_string<uint8_t> _ctx;
    std::vector<tls_extension> _extensions;
public:
    virtual handshake_type type() const override { return HT_CERTIFICATE_REQUEST; }
    virtual size_t serialize(std::basic_ostringstream<uint8_t>&) override;
    virtual void deserialize(std::basic_istringstream<uint8_t>&) override;
    virtual size_t size() const override;
};

}
}

#endif
