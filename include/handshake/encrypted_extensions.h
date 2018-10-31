#ifndef _TUN_HANDSHAKE_ENCRYPTED_EXTENSIONS_
#define _TUN_HANDSHAKE_ENCRYPTED_EXTENSIONS_

#include "handshake/entity.h"
#include "handshake/tls_extension.h"
#include <vector>
#include <cstdint>

namespace tun {
namespace handshake {

class encrypted_extensions : public entity {
private:
    std::vector<tls_extension> _extensions;
public:
    std::vector<tls_extension>& extensions() { return this->_extensions; }

    virtual handshake_type type() const override { return HT_ENCRYPTED_EXTENSIONS; }
    virtual size_t serialize(std::basic_ostringstream<uint8_t>&) override;
    virtual void deserialize(std::basic_istringstream<uint8_t>&) override;
    virtual size_t size() const override;
};

}
}

#endif
