#ifndef _TUN_HANDSHAKE_NEW_SESSION_TICKET_
#define _TUN_HANDSHAKE_NEW_SESSION_TICKET_

#include "handshake/entity.h"
#include "handshake/tls_extension.h"
#include <cstdint>
#include <string>
#include <vector>

namespace tun {
namespace handshake {

class new_session_ticket : public entity {
private:
    uint32_t _lifetime;
    uint32_t _age_add;
    std::basic_string<uint8_t> _nonce;
    std::basic_string<uint8_t> _ticket;
    std::vector<tls_extension> _extensions;
public:
    uint32_t& lifetime() { return this->_lifetime; }
    uint32_t& age_add() { return this->_age_add; }
    std::basic_string<uint8_t>& nonce() { return this->_nonce; }
    std::basic_string<uint8_t>& ticket() { return this->_ticket; }
    std::vector<tls_extension>& extensions() { return this->_extensions; }

    virtual handshake_type type() const override { return HT_NEW_SESSION_TICKET; }
    virtual size_t serialize(std::basic_ostringstream<uint8_t>&) override;
    virtual void deserialize(std::basic_istringstream<uint8_t>&) override;
    virtual size_t size() const override;
};

}
}

#endif
