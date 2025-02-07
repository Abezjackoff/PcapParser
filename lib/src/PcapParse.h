#ifndef PCAP_PARSE_H
#define PCAP_PARSE_H

#include <cstdint>
#include <cstring>

template<typename T>
size_t read_PcapSection(const char* raw, size_t rawLen, T* data, size_t dataLen)
{
    size_t actLen = std::min(rawLen, dataLen);
    std::memcpy(data, raw, actLen);
    data->dser_callback();
    return actLen;
}

inline uint16_t swap_bytes(const uint16_t& x){
    return ((x & 0x00FF) << 8) | ((x & 0xFF00) >> 8);
}

inline uint32_t swap_bytes(const uint32_t& x){
    return ((x & 0x000000FF) << 24) | ((x & 0x0000FF00) << 8) |
           ((x & 0x00FF0000) >> 8) | ((x & 0xFF000000) >> 24);
}

#endif
