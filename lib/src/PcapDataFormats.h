#ifndef PCAP_DATA_FORMATS_H
#define PCAP_DATA_FORMATS_H

#include <cstddef>
#include <cstdint>
#include <sstream>

#include "PcapParse.h"

struct __attribute__((packed))
FileHeader
{
    uint32_t magicNumber {};    // 0xA1B2C3D4 or 0xA1B23C4D
    uint16_t majorVersion {};   // 2
    uint16_t minorVersion {};   // 4
    uint32_t reserved1 {};
    uint32_t reserved2 {};
    uint32_t snapLen {};
    char rawField1[2] {}; 
    uint16_t linkType {};

    uint8_t fcs {};
    bool f {};

    static const size_t len {24};
    void dser_callback(){
        // Decompose
        fcs = rawField1[0] >> 5;
        f =  (rawField1[0] & 0x10) >> 4;
    }
};

struct __attribute__((packed))
RecordHeader
{
    uint32_t timestamp {};      // [s]
    uint32_t timestampFrac {};  // [mus] or [ns]
    uint32_t capdPacketLen {};
    uint32_t origPacketLen {};

    static const size_t len {16};
    void dser_callback(){}
    std::string print() const {
        std::string unit;
        if      (timeFracUnit == TimeFracUnit::mus) unit = "\"mus\"";
        else if (timeFracUnit == TimeFracUnit::ns)  unit = "\"ns\"";
        else                                        unit = "\"\"";
        std::stringstream ss;
        ss << "\"Timestamp\": {\"Value\": "         << timestamp     << ", \"Unit\": \"s\"}, ";
        ss << "\"TimestampFraction\": {\"Value\": " << timestampFrac << ", \"Unit\": " << unit << "}";
        
        return ss.str();
    }
    void set_timeFracUnit(const uint32_t magicNumber){
        if      (magicNumber == 0xA1B2C3D4) timeFracUnit = mus;
        else if (magicNumber == 0xA1B23C4D) timeFracUnit = ns;
        else                                timeFracUnit = NA;
    };
    enum TimeFracUnit {
        NA = 0,
        mus = 1,
        ns = 2
    } timeFracUnit {NA};
};

struct __attribute__((packed))
LinkNullHeader
{
    uint32_t protocol {};       // 2 - IPv4; 24, 28, 30 - IPv6

    static const size_t len {1}; 
    void dser_callback(){}
};

struct __attribute__((packed))
LinkEthHeader
{
    char dstMac[6] {};
    char srcMac[6] {};
    char ethType[2] {};

    static const size_t len {14};
    void dser_callback(){}
};

struct __attribute__((packed))
IpHeader
{
    char rawField1 {};
    uint8_t typeOfService {};
    uint16_t totalLength {};
    uint16_t identification {};
    char rawField2[2] {};
    uint8_t timeToLive {};
    uint8_t protocol {};        // 6 - TCP, 17 - UDP
    uint16_t headerChecksum {};
    uint32_t sa {};
    uint32_t da {};
    char *options;

    uint8_t version {};         // 4 or 6
    uint8_t headerLength {};    // >= 5

    static const size_t len {20};
    void dser_callback(){
        // Decompose
        version =      rawField1 >> 4;
        headerLength = rawField1 & 0x0F;
        // Big-endian to little-endian
        totalLength = swap_bytes(totalLength);
        identification = swap_bytes(identification);
        headerChecksum = swap_bytes(headerChecksum);
        sa = swap_bytes(sa);
        da = swap_bytes(da);
    }
    std::string print() const {   
        std::string protocolName;
        if      (protocol == TCP) protocolName = "\"TCP\"";
        else if (protocol == UDP) protocolName = "\"UDP\"";
        else                                protocolName = "\"Other\"";
        std::stringstream ss;
        ss << "\"Internet\": " << "\"IPv"    << uint(version) << "\", ";
        ss << "\"Protocol\": "               << protocolName << ", ";
        ss << "\"SourceAddress\": \"0x"      << std::hex << sa << "\", ";
        ss << "\"DestinationAddress\": \"0x" << da << "\"" << std::dec;
        
        return ss.str();
    }
    enum Protocol {
        TCP = 6,
        UDP = 17
    };
};

struct __attribute__((packed))
UdpHeader
{
    uint16_t srcPort {};
    uint16_t dstPort {};
    uint16_t length {};
    uint16_t checksum {};

    static const size_t len {8};
    void dser_callback(){
        // Big-endian to little-endian
        srcPort = swap_bytes(srcPort);
        dstPort = swap_bytes(dstPort);
        length = swap_bytes(length);
        checksum = swap_bytes(checksum);
    }
    std::string print() const {
        std::stringstream ss;
        ss << "\"SourcePort\": "      << srcPort << ", ";
        ss << "\"DestinationPort\": " << dstPort << ", ";
        ss << "\"Length\": "          << length;
        
        return ss.str();
    }
};

struct __attribute__((packed))
MarketDataHeader
{
    uint32_t msgSeqNum {};
    uint16_t msgSize {};
    uint16_t msgFlags {};
    uint64_t sendingTime {};

    static const size_t len {16};
    void dser_callback(){}
    std::string print() const {
        std::stringstream ss;
        ss << "\"MsgSeqNum\": "    << msgSeqNum << ", ";
        ss << "\"MsgSize\": "      << msgSize   << ", ";
        ss << "\"MsgFlags\": \"0x" << std::hex  << msgFlags << std::dec << "\", ";
        ss << "\"SendingTime\": "  << sendingTime;

        return ss.str();
    }
    bool is_lastFragment()    { return msgFlags & 0x1; }
    bool is_startOfSnapshot() { return msgFlags & 0x2; }
    bool is_endOfSnapshot()   { return msgFlags & 0x4; }
    bool is_incremental()     { return msgFlags & 0x8; }
};

struct __attribute__((packed))
IncrementalHeader
{
    uint64_t transactTime {};
    uint32_t sessionId {};

    static const size_t len {12};
    void dser_callback(){}
    std::string print() const {
        std::ostringstream ss;
        ss << "\"TransactTime\": "             << transactTime << ", ";
        ss << "\"ExchangeTradingSessionID\": " << sessionId;

        return ss.str();
    }
};

struct __attribute__((packed))
SbeHeader
{
    uint16_t blockLength {};
    uint16_t templateId {};
    uint16_t schemaId {};
    uint16_t version {};

    static const size_t len {8};
    void dser_callback(){}
    std::string print() const {
        std::ostringstream ss;
        ss << "\"BlockLength\": " << blockLength << ", ";
        ss << "\"TemplateID\": "  << templateId << ", ";
        ss << "\"SchemaID\": "    << schemaId << ", ";
        ss << "\"Version\": "     << version;
        
        return ss.str();
    }
    enum MsgId {
        OrderUpdateId = 15,
        OrderExecutionId = 16,
        OrderBookSnapshotId = 17
    };
};

struct __attribute__((packed))
GroupSize
{
    uint16_t blockLength {};
    uint8_t numInGroup {};

    static const size_t len {3};
    void dser_callback(){}
    std::string print() const {
        std::ostringstream ss;
        ss << "\"BlockLength\": " << blockLength << ", ";
        ss << "\"NumInGroup\": "  << uint(numInGroup);

        return ss.str();
    }
};

// ID = 15
struct __attribute__((packed))
OrderUpdate
{
    int64_t mdEntryId {};
    int64_t mdEntryPxRaw {};
    int64_t mdEntrySize {};
    uint64_t mdFlags {};
    uint64_t mdFlags2 {};
    int32_t securityId {};
    uint32_t rptSeq {};
    uint8_t mdUpdateAction {};
    char mdEntryType {};

    double mdEntryPx {};

    static const size_t len {50};
    void dser_callback(){
        mdEntryPx = mdEntryPxRaw * 1e-5;
    }
    std::string print() const {
        std::ostringstream ss;
        ss << "\"MDEntryID\": "     << mdEntryId << ", ";
        ss << "\"MDEntryPx\": "     << mdEntryPx << ", ";
        ss << "\"MDEntrySize\": "   << mdEntrySize << ", ";
        ss << "\"MDFlags\": \"0x"   << std::hex << mdFlags << "\", ";
        ss << "\"MDFlags2\": \"0x"  << mdFlags << std::dec << "\", ";
        ss << "\"SecurityID\": "    << securityId << ", ";
        ss << "\"RptSeq\": "        << rptSeq    << ", ";
        ss << "\"MDUpdateAction\": " << uint(mdUpdateAction) << ", ";
        ss << "\"MDEntryType\": \"" << mdEntryType << "\"";
        
        return ss.str();
    }
};

// ID = 16
struct __attribute__((packed))
OrderExecution
{
    int64_t mdEntryId {};
    int64_t mdEntryPxRaw {};
    int64_t mdEntrySize {};
    int64_t lastPxRaw {};
    int64_t lastQty {};
    int64_t tradeId {};
    uint64_t mdFlags {};
    uint64_t mdFlags2 {};
    int32_t securityId {};
    uint32_t rptSeq {};
    uint8_t mdUpdateAction {};
    char mdEntryType {};

    double mdEntryPx {};
    double lastPx {};

    static const size_t len {74};
    void dser_callback(){
        mdEntryPx = mdEntryPxRaw * 1e-5;
        lastPx = lastPxRaw * 1e-5;
    }
    std::string print() const {
        std::ostringstream ss;
        ss << "\"MDEntryID\": "     << mdEntryId << ", ";
        ss << "\"MDEntryPx\": "     << mdEntryPx << ", ";
        ss << "\"MDEntrySize\": "   << mdEntrySize << ", ";
        ss << "\"LastPx\": "        << lastPx << ", ";
        ss << "\"LastQty\": "       << lastQty << ", ";
        ss << "\"TradeID\": "       << tradeId << ", ";
        ss << "\"MDFlags\": \"0x"   << std::hex << mdFlags << "\", ";
        ss << "\"MDFlags2\": \"0x"  << mdFlags << std::dec << "\", ";
        ss << "\"SecurityID\": "    << securityId << ", ";
        ss << "\"RptSeq\": "        << rptSeq    << ", ";
        ss << "\"MDUpdateAction\": " << uint(mdUpdateAction) << ", ";
        ss << "\"MDEntryType\": \"" << mdEntryType << "\"";
        
        return ss.str();
    }
};

// ID = 17
struct OrderBookSnapshot
{
    struct __attribute__((packed))
    Root {
        int32_t secuirityId {};
        uint32_t lastMsgSeqNum {};
        uint32_t rptSeq {};
        uint32_t sessionId {};

        static const size_t len {16};
        void dser_callback(){}
        std::string print() const
        {
            std::ostringstream ss;
            ss << "\"SecurityID\": "               << secuirityId << ", ";
            ss << "\"LastMsgSeqNumProcessed\": "   << lastMsgSeqNum << ", ";
            ss << "\"RptSeq\": "                   << rptSeq << ", ";
            ss << "\"ExchangeTradingSessionID\": " << sessionId;

            return ss.str();
        }
    } root;

    GroupSize groupSize;

    struct __attribute__((packed))
    Group {
        int64_t mdEntryId {};
        uint64_t transactTime {};
        int64_t mdEntryPxRaw {};
        int64_t mdEntrySize {};
        int64_t tradeId {};
        uint64_t mdFlags {};
        uint64_t mdFlags2 {};
        char mdEntryType {};

        double mdEntryPx {};

        static const size_t len {57};
        void dser_callback(){
            mdEntryPx = mdEntryPxRaw * 1e-5;
        }
        std::string print() const
        {
            std::ostringstream ss;
            ss << "\"MDEntryID\": "     << mdEntryId << ", ";
            ss << "\"TransactTime\": "  << transactTime << ", ";
            ss << "\"MDEntryPx\": "     << mdEntryPx << ", ";
            ss << "\"MDEntrySize\": "   << mdEntrySize << ", ";
            ss << "\"TradeID\": "       << tradeId << ", ";
            ss << "\"MDFlags\": \"0x"   << std::hex << mdFlags << "\", ";
            ss << "\"MDFlags2\": \"0x"  << mdFlags << std::dec << "\", ";
            ss << "\"MDEntryType\": \"" << mdEntryType << "\"";

            return ss.str();
        }
    } group;
};

#endif
