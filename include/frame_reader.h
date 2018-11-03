#ifndef _TUN_FRAME_READER_
#define _TUN_FRAME_READER_

#include "framing.h"
#include <cstdint>
#include <string>
#include <tuple>

namespace tun {

enum frame_reader_status : uint8_t {
    FRS_HEADER,
    FRS_PAYLOAD
};

class frame_reader {
private:
    framing& _info;
    frame_reader_status _state;
    std::basic_string<uint8_t> _header;
    std::basic_string<uint8_t> _payload;
    std::basic_string<uint8_t> *_buf;
    size_t _off;
    std::basic_string<uint8_t> _remain;
public:
    frame_reader(framing&);
    size_t needed() const;
    void add_chunk(std::basic_string<uint8_t>&);
    std::tuple<std::basic_string<uint8_t>, std::basic_string<uint8_t>, bool> process();
};

}

#endif
