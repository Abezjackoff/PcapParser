# PCAP Parser

## About
This project contains source files of the CLI application
and the executable for Linux.

## Usage

1. Navigate to the `build` folder where the executable is located:
   - `cd build`
2. Launch the application with 1 or 2 arguments:
   - `./PcapParser ${pcap_file} ${records_count}`\
   where
     - `${pcap_file}` is a path to the input file (e.g. `./input.pcap`) &emsp;&emsp; -- mandatory
     - `${records_count}` is a number of records to process (e.g. `200000`) -- optional
3. Check out `${pcap_file}.json` file where output is printed out (e.g. `./input.pcap.json`).

Note, that the arguments are positional.\
If the 1st (mandatory) argument is not defined,
then the application attempts to read from the default file `../data/test.pcap`.\
If the 2nd (optional) argument is not defined,
then all records available in a given PCAP file are processed.

## File Structure

### src
This folder contains `main.cpp` file of the application.

### lib
This folder contains source files of a static library for reading PCAP files and decoding MD messages.

### build
This folder contains the executable. 

### data
This folder contains `test.pcap` file used as the default input.
