#include "PcapFileHandler.h"

#include <stdexcept>
#include <sstream>

#include "Logging.h"
#include "TextToTable.h"

PcapFileHandler::PcapFileHandler(const std::string& ifName, const std::string& ofName)
{
    inpFile_ = std::make_shared<std::ifstream>(ifName, std::ios::in | std::ios::binary);

    if (!inpFile_->is_open())
        throw std::runtime_error("Cannot open or read from PCAP file!");

    read_fileHeader();
    recHeaderNow.set_timeFracUnit(fileHeader.magicNumber);

    std::string outFileName;
    if (ofName.empty() || ofName == ifName)
        outFileName = ifName + ".json";
    else
        outFileName = ofName;
    outFile_ = std::make_shared<std::ofstream>(outFileName, std::ios::out | std::ios::trunc);
    
    if (outFile_->fail())
        throw std::runtime_error("Cannot open or write to JSON file!");

    udpParser_ = std::make_unique<UdpParser>(
        std::static_pointer_cast<std::istream>(std::shared_ptr<std::ifstream>(inpFile_)),
        std::static_pointer_cast<std::ostream>(std::shared_ptr<std::ofstream>(outFile_))
    );
}

void PcapFileHandler::read_fileHeader()
{
    inpFile_->read(buffer, FileHeader::len);
    read_PcapSection(buffer, FileHeader::len, &fileHeader, FileHeader::len);
    
    std::stringstream ss;
    TextToTable table;
    table.new_row();
    ss << "MagicNumber: 0x" << std::hex << fileHeader.magicNumber << std::dec;
    table.add_cell(ss.str()); ss.str(""); ss.clear();
    
    table.new_row();
    ss << "MajorVersion: " << fileHeader.majorVersion;
    table.add_cell(ss.str()); ss.str(""); ss.clear();
    ss << "MinorVersion: " << fileHeader.minorVersion;
    table.add_cell(ss.str()); ss.str(""); ss.clear();

    table.new_row();
    table.add_cell("---");

    table.new_row();
    table.add_cell("---");

    table.new_row();
    ss << "SnapLen: " << fileHeader.snapLen;
    table.add_cell(ss.str()); ss.str(""); ss.clear();

    table.new_row();
    ss << "FCS: " << uint(fileHeader.fcs);
    table.add_cell(ss.str()); ss.str(""); ss.clear();
    ss << "f: " << uint(fileHeader.f);
    table.add_cell(ss.str()); ss.str(""); ss.clear();
    table.add_cell("---");
    ss << "LinkType: " << fileHeader.linkType;
    table.add_cell(ss.str()); ss.str(""); ss.clear();
    
    console_log("Decoded PCAP header:\n" + table.print(), LogLevel::INFO);
}

uint64_t PcapFileHandler::read_records(bool withLim, uint64_t nLim)
{
    uint64_t i {};
    while ((!withLim || i < nLim) && read_nextRecord()){ 
        i++;
        if (i % 100000 == 0){
            outFile_->flush();
            console_log(std::to_string(i) + " scanned", LogLevel::INFO);
        }
    };
    return i;
}

bool PcapFileHandler::read_nextRecord()
{
    // Read record header
    inpFile_->read(buffer, RecordHeader::len);
    read_PcapSection(buffer, RecordHeader::len, &recHeaderNow, RecordHeader::len);
    size_t nextRecPos = size_t(inpFile_->tellg()) + recHeaderNow.capdPacketLen;

    // Skip Ethernet link header
    // Should it depend on fileHeader.linkType?
    inpFile_->seekg(size_t(inpFile_->tellg()) + LinkEthHeader::len);
    
    // Read IP header
    inpFile_->read(buffer, IpHeader::len);
    read_PcapSection(buffer, IpHeader::len, &ipHeaderNow, IpHeader::len);
    
    // Skip IP options
    size_t ipOptLen = std::max(4 * int(ipHeaderNow.headerLength) - int(IpHeader::len), 0);
    inpFile_->seekg(size_t(inpFile_->tellg()) + ipOptLen);

    if (ipHeaderNow.protocol == IpHeader::Protocol::UDP){
        // Convert headers to text for output
        udpParser_->set_packetContext(recHeaderNow, ipHeaderNow);
        // Read UDP packet
        size_t udpAvailableLen = std::max(int(ipHeaderNow.totalLength) - 4 * int(ipHeaderNow.headerLength), 0);
        udpParser_->decode_udpData(udpAvailableLen);
    }
    else {
        // Skip TCP and other packets
        ;
    }

    inpFile_->seekg(nextRecPos);
    return (inpFile_->tellg() != std::streampos(-1));
}
