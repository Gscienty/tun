#ifndef _TUN_HANDSHAKE_SERVER_HELLO_
#define _TUN_HANDSHAKE_SERVER_HELLO_

#include "handshake/entity.h"
#include "handshake/type.h"
#include "handshake/tls_extension.h"
#include <string>
#include <vector>

namespace tun {
namespace handshake {

class server_hello : public entity {
private:
    protocol_version_t _version;
    std::basic_string<uint8_t> _random;
    std::basic_string<uint8_t> _legacy_session_id;
    cipher_suite_t _cipher_suite;
    uint8_t _legacy_compression_method;
    std::vector<tls_extension> _extensions;
public:
    server_hello();

    virtual handshake_type type() const override { return HT_SERVER_HELLO; }

    protocol_version_t& version() { return this->_version; }
    std::basic_string<uint8_t>& random() { return this->_random; }
    std::basic_string<uint8_t>& legacy_session_id() { return this->_legacy_session_id; }
    cipher_suite_t& cipher_suite() { return this->_cipher_suite; }
    uint8_t& legacy_compression_method() { return this->_legacy_compression_method; }
    std::vector<tls_extension>& extensions() { return this->_extensions; }

    virtual size_t serialize(std::basic_ostringstream<uint8_t>&) override;
    virtual void deserialize(std::basic_istringstream<uint8_t>&) override;
    virtual size_t size() const override;

    bool operator== (const server_hello&) const;
    bool operator!= (const server_hello&) const;
};

}
}

#endif
