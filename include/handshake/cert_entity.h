#ifndef _TUN_HANDSHAKE_CERT_ENTITY_
#define _TUN_HANDSHAKE_CERT_ENTITY_

#include "handshake/tls_extension.h"
#include "handshake/entity.h"
#include <string>
#include <cstdint>
#include <vector>

namespace tun {
namespace handshake {

class cert_entity : public entity {
private:
    std::basic_string<uint8_t> _data;
    std::vector<tls_extension> _extensions;
public:
    virtual handshake_type type() const override { return HT_CERTIFICATE; }
    virtual size_t serialize(std::basic_ostringstream<uint8_t>&) override;
    virtual void deserialize(std::basic_istringstream<uint8_t>&) override;
    virtual size_t size() const override;
};

}
}

#endif
