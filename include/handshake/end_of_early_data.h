#ifndef _TUN_HANDSHAKE_END_OF_EARLY_DATA_
#define _TUN_HANDSHAKE_END_OF_EARLY_DATA_

#include "handshake/entity.h"

namespace tun {
namespace handshake {

class end_of_early_data : public entity {
public:
    virtual handshake_type type() const override { return HT_END_OF_EARLY_DATA; }
    virtual size_t serialize(std::basic_ostringstream<uint8_t>&) override { return 0; }
    virtual void deserialize(std::basic_istringstream<uint8_t>&) override {  }
    virtual size_t size() const override { return 0; }
};

}
}

#endif
