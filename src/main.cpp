#include <string>
#include <iostream>
#include <fstream>

#include "../lib/include/Logging.h"
#include "../lib/src/PcapFileHandler.h"

int main(int argc, char** argv)
{   
    std::string ifName;
    if (argc > 1){
        ifName = argv[1];
    }
    else {
        ifName = "../data/test.pcap";
        console_log("Input file not specified! Trying to access a default file...", LogLevel::WARNING);
        console_log("(To read from a specific file set it as the 1st argument of this CLI app)");
        console_log();
    }
    std::string ofName = ifName + ".json";
    
    int nLim {};
    if (argc > 2){
        nLim = std::atoi(argv[2]);
    }
    else {
        console_log("Number of records to read is not specified! Processing the whole file...", LogLevel::INFO);
        console_log("(To limit a number of records set it as the 2nd argument of this CLI app)");
        console_log();
    }
    bool withLim = nLim > 0;
    
    console_log("Processing data from PCAP file: \"" + ifName + "\"...", LogLevel::INFO);
    try {
        PcapFileHandler pcapFileHandler {ifName, ofName};
        
        console_log();
        console_log("Reading records...", LogLevel::INFO);
        uint64_t nRec = pcapFileHandler.read_records(withLim, nLim);
        
        console_log();
        console_log("Done! Scanned " + std::to_string(nRec) + " records", LogLevel::INFO);
        console_log("Output is saved to JSON file: \"" + ofName + "\"", LogLevel::INFO);
    }
    catch (std::exception& e){
        console_log();
        console_log(e.what(), LogLevel::ERROR);
        console_log("No valid output produced", LogLevel::INFO);
    }

    console_log("Press ENTER to exit...");
    std::cin.get();
    return 0;
}
