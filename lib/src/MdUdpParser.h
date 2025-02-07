#ifndef MD_UDP_PARSER_H
#define MD_UDP_PARSER_H

#include <memory>
#include <iostream> 

#include "PcapDataFormats.h"

class UdpParser
{
public:
    UdpParser(std::shared_ptr<std::istream> inp, std::shared_ptr<std::ostream> out);

    void set_packetContext(const RecordHeader& recHeaderNow, const IpHeader& ipHeaderNow);
    bool decode_udpData(size_t udpAvailableLen);

private:
    bool process_incMessage(const SbeHeader& sbeHeader, size_t& remainLen);
    bool process_snapMessage(const SbeHeader& sbeHeader, size_t& remainLen);
    void init_msgToJson();
    void add_mdHeaderToJson();
    void add_incHeaderToJson();
    void add_snapHeaderToJson();
    void add_incMsgToJson(const std::string& s);
    void add_snapRootMsgToJson(const std::string& s);
    void add_snapSizeMsgToJson(const std::string& s);
    void add_snapGroupMsgToJson(const std::string& s);
    void begin_arrToJson();
    void begin_objToJson();
    void end_arrToJson();
    void end_objToJson();
    void send_msgToJson();


    char hdrBuffer[16] {};
    char msgBuffer[100] {};
    UdpHeader udpHeaderNow;
    MarketDataHeader mdHeader;
    IncrementalHeader incHeader;
    SbeHeader sbeHeader;
    size_t msgCapdCount {};
    std::string packetContext;
    std::string outBuffer;
    std::shared_ptr<std::istream> input_;
    std::shared_ptr<std::ostream> output_;
};

#endif
