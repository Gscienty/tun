#ifndef _TUN_HANDSHAKE_CERT_BODY_
#define _TUN_HANDSHAKE_CERT_BODY_

#include "handshake/entity.h"
#include "handshake/cert_entity.h"
#include <string>
#include <vector>

namespace tun {
namespace handshake {

class cert_body : public entity {
private:
    std::basic_string<uint8_t> _ctx;
    std::vector<cert_entity> _certs;
public:
    virtual handshake_type type() const override { return HT_CERTIFICATE; }
    virtual size_t serialize(std::basic_ostringstream<uint8_t>&) override;
    virtual void deserialize(std::basic_istringstream<uint8_t>&) override;
    virtual size_t size() const override; 
};
} 
} 
#endif
