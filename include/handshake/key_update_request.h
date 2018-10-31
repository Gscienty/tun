#ifndef _TUN_HANDSHAKE_KEY_UPDATE_REQUEST_
#define _TUN_HANDSHAKE_KEY_UPDATE_REQUEST_

#include "handshake/type.h"
#include "handshake/entity.h"

namespace tun {
namespace handshake {

class key_update_request : public entity {
private:
    key_update_request_t _key_update_request;
public:
    virtual handshake_type type() const override { return HT_KEY_UPDATE; }
    virtual size_t serialize(std::basic_ostringstream<uint8_t>&) override;
    virtual void deserialize(std::basic_istringstream<uint8_t>&) override;
    virtual size_t size() const override;
};

}
}

#endif
