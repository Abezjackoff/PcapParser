#ifndef PCAP_FILE_HANDLER_H
#define PCAP_FILE_HANDLER_H

#include <fstream>
#include <string>
#include <memory>

#include "PcapDataFormats.h"
#include "MdUdpParser.h"

class PcapFileHandler
{
public:
    PcapFileHandler(const std::string& fName, const std::string& ofName);

    uint64_t read_records(bool withLim, uint64_t nLim);
    bool read_nextRecord();

private:
    void read_fileHeader();
    
    char buffer[24] {};
    FileHeader fileHeader;
    RecordHeader recHeaderNow;
    IpHeader ipHeaderNow;
    std::shared_ptr<std::ifstream> inpFile_;
    std::shared_ptr<std::ofstream> outFile_;
    std::unique_ptr<UdpParser> udpParser_;
};

#endif
