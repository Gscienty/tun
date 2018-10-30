#ifndef _TUN_HANDSHAKE_CLIENT_HELLO_
#define _TUN_HANDSHAKE_CLIENT_HELLO_

#include "handshake/type.h"
#include "handshake/tls_extension.h"
#include "handshake/entity.h"
#include <string>
#include <sstream>
#include <vector>

namespace tun {
namespace handshake {

class client_hello : public entity {
private:
    protocol_version_t _legacy_version;
    std::basic_string<uint8_t> _random;
    std::basic_string<uint8_t> _legacy_session_id;
    std::vector<cipher_suite_t> _cipher_suites;
    std::basic_string<uint8_t> _legacy_compression_methods;
    std::vector<tls_extension> _extensions;
public:
    client_hello();

    virtual handshake_type type() const override { return HT_CLIENT_HELLO; }

    protocol_version_t& legacy_version() { return this->_legacy_version; }
    std::basic_string<uint8_t>& random() { return this->_random; }
    std::basic_string<uint8_t>& legacy_session_id() { return this->_legacy_session_id; }
    std::vector<cipher_suite_t>& cipher_suites() { return this->_cipher_suites; }
    std::basic_string<uint8_t>& legacy_compression_methods() { return this->_legacy_compression_methods; }
    std::vector<tls_extension>& extensions() { return this->_extensions; }

    virtual size_t serialize(std::basic_ostringstream<uint8_t>&) override;
    virtual void deserialize(std::basic_istringstream<uint8_t>&) override;
    virtual size_t size() const override;

    bool operator== (const client_hello&) const;
    bool operator!= (const client_hello&) const;
};

}
}
#endif
