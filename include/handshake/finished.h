#ifndef _TUN_HANDSHAKE_FINISHED_
#define _TUN_HANDSHAKE_FINISHED_

#include "handshake/entity.h"
#include <string>

namespace tun {
namespace handshake {

class finished : public entity {
private:
    size_t _len;
    std::basic_string<uint8_t> _data;
public:
    size_t& len() { return this->_len; }
    std::basic_string<uint8_t>& data() { return this->_data; }

    virtual handshake_type type() const override { return HT_FINISHED; }
    virtual size_t serialize(std::basic_ostringstream<uint8_t>&) override;
    virtual void deserialize(std::basic_istringstream<uint8_t>&) override;
    virtual size_t size() const override;
};

}
}

#endif
