#include "frame_reader.h"
#include <algorithm>

namespace tun {

frame_reader::frame_reader(framing& info) : _info(info), _off(0) {
    this->_header.resize(info.header_size(), 0);
    this->_state = FRS_HEADER;
    this->_buf = &this->_header;
}

size_t frame_reader::needed() const {
    size_t buf_size = 0;
    if (this->_buf != nullptr) {
        buf_size = this->_buf->size();
    }
    return std::max(0,
                    static_cast<int>(buf_size) -
                    static_cast<int>(this->_off) -
                    static_cast<int>(this->_remain.size()));
}

void frame_reader::add_chunk(std::basic_string<uint8_t>& chunk) {
    this->_remain.append(chunk);
}

std::tuple<std::basic_string<uint8_t>, std::basic_string<uint8_t>, bool> frame_reader::process() {
    while (this->needed() == 0) {
        size_t copied = std::min(this->_buf->size() - this->_off, this->_remain.size());
        std::copy_n(this->_remain.begin(), copied, this->_buf->begin() + this->_off);
        this->_buf += copied;
        if (this->_off < this->_buf->size()) {
            return std::make_tuple(std::basic_string<uint8_t>(), std::basic_string<uint8_t>(), false);
        }
        this->_off = 0;

        if (this->_state == FRS_PAYLOAD) {
            this->_state = FRS_HEADER;
            this->_buf = &this->_header;
            return std::make_tuple(std::basic_string<uint8_t>(this->_header),
                                   std::basic_string<uint8_t>(this->_payload),
                                   false);
        }

        size_t payload_length = this->_info.payload_size(this->_header);

        this->_payload.resize(payload_length, 0);
        this->_buf = &this->_payload;
        this->_off = 0;
        this->_state = FRS_PAYLOAD;
    }

    return std::make_tuple(std::basic_string<uint8_t>(), std::basic_string<uint8_t>(), false);
}



}
