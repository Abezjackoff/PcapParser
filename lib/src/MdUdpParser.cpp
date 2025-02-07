#include "MdUdpParser.h"

UdpParser::UdpParser(std::shared_ptr<std::istream> inp, std::shared_ptr<std::ostream> out)
: input_ {inp}, output_ {out}
{
    outBuffer.reserve(UINT16_MAX);
}

void UdpParser::set_packetContext(const RecordHeader& recHeaderNow, const IpHeader& ipHeaderNow)
{
    packetContext.clear();
    packetContext.append(recHeaderNow.print());
    packetContext.append(", ");
    packetContext.append(ipHeaderNow.print());
}

bool UdpParser::decode_udpData(size_t udpAvailableLen)
{
    // Should it be filtered by SA/DA or ports?
    if (udpAvailableLen > UdpHeader::len){
        input_->read(hdrBuffer, UdpHeader::len);
        udpAvailableLen -= read_PcapSection(hdrBuffer, UdpHeader::len, &udpHeaderNow, UdpHeader::len);
    }
    else return false;

    if (udpAvailableLen > MarketDataHeader::len){
        input_->read(hdrBuffer, MarketDataHeader::len);
        udpAvailableLen -= read_PcapSection(hdrBuffer, MarketDataHeader::len, &mdHeader, MarketDataHeader::len);
    }
    else return false;
    
    bool msgCaptured = false;
    init_msgToJson();
    if (udpAvailableLen > (IncrementalHeader::len + SbeHeader::len)
        && mdHeader.is_incremental())
    {
        input_->read(hdrBuffer, IncrementalHeader::len);
        udpAvailableLen -= read_PcapSection(hdrBuffer, IncrementalHeader::len, &incHeader, IncrementalHeader::len);
        add_incHeaderToJson();

        while (udpAvailableLen > SbeHeader::len)
        {
            input_->read(hdrBuffer, SbeHeader::len);
            udpAvailableLen -= read_PcapSection(hdrBuffer, SbeHeader::len, &sbeHeader, SbeHeader::len);

            if (udpAvailableLen >= sbeHeader.blockLength){
                msgCaptured = process_incMessage(sbeHeader, udpAvailableLen);
            }
            else break;
        }
    }
    else if (udpAvailableLen > SbeHeader::len && !mdHeader.is_incremental())
    {
        add_snapHeaderToJson();

        input_->read(hdrBuffer, SbeHeader::len);
        udpAvailableLen -= read_PcapSection(hdrBuffer, SbeHeader::len, &sbeHeader, SbeHeader::len);

        if (udpAvailableLen >= sbeHeader.blockLength){
            msgCaptured = process_snapMessage(sbeHeader, udpAvailableLen);
        }
    }
    if (msgCaptured) send_msgToJson();
    return msgCaptured;
}

bool UdpParser::process_incMessage(const SbeHeader& sbeHeader, size_t& remainLen)
{
    input_->read(msgBuffer, sbeHeader.blockLength);
    if (sbeHeader.templateId == SbeHeader::OrderUpdateId){
        OrderUpdate orderUpdate;
        remainLen -= read_PcapSection(msgBuffer, sbeHeader.blockLength, &orderUpdate, OrderUpdate::len);
        add_incMsgToJson(orderUpdate.print());
        return true;
    }
    if (sbeHeader.templateId == SbeHeader::OrderExecutionId){
        OrderExecution orderExecution;
        remainLen -= read_PcapSection(msgBuffer, sbeHeader.blockLength, &orderExecution, OrderExecution::len);
        add_incMsgToJson(orderExecution.print());
        return true;
    }
    if (sbeHeader.templateId == SbeHeader::OrderBookSnapshotId){
        OrderBookSnapshot orderBookSnapshot;
        remainLen -= read_PcapSection(msgBuffer, sbeHeader.blockLength, &orderBookSnapshot.root, OrderBookSnapshot::Root::len);
        add_incMsgToJson(orderBookSnapshot.root.print());
        return true;
    }
    return false;
}

bool UdpParser::process_snapMessage(const SbeHeader& sbeHeader, size_t& remainLen)
{
    input_->read(msgBuffer, sbeHeader.blockLength);
    if (sbeHeader.templateId == SbeHeader::OrderBookSnapshotId){
        begin_objToJson();
        OrderBookSnapshot orderBookSnapshot;
        remainLen -= read_PcapSection(msgBuffer, sbeHeader.blockLength, &orderBookSnapshot.root, OrderBookSnapshot::Root::len);
        add_snapRootMsgToJson(orderBookSnapshot.root.print());

        if (remainLen > GroupSize::len){
            input_->read(msgBuffer, GroupSize::len);
            remainLen -= read_PcapSection(msgBuffer, GroupSize::len, &orderBookSnapshot.groupSize, GroupSize::len);
            add_snapSizeMsgToJson(orderBookSnapshot.groupSize.print());

            begin_arrToJson();
            while (remainLen >= orderBookSnapshot.groupSize.blockLength){
                input_->read(msgBuffer, orderBookSnapshot.groupSize.blockLength);
                remainLen -= read_PcapSection(msgBuffer, orderBookSnapshot.groupSize.blockLength,
                                                     &orderBookSnapshot.group, OrderBookSnapshot::Group::len);
                add_snapGroupMsgToJson(orderBookSnapshot.group.print());
            }
            end_arrToJson();
        }
        end_objToJson();
        return true;
    }
    return false;
}

void UdpParser::init_msgToJson()
{
    msgCapdCount = 0;
    outBuffer.clear();
    outBuffer.append("{");
    outBuffer.append(packetContext);
    outBuffer.append(", \"UDPHeader\": {");
    outBuffer.append(udpHeaderNow.print());
    outBuffer.append("}, \"Packet\": ");
}

void UdpParser::add_mdHeaderToJson()
{
    outBuffer.append("\"MDPacketHeader\": {");
    outBuffer.append(mdHeader.print());
    outBuffer.append("}");
}

void UdpParser::add_incHeaderToJson()
{
    outBuffer.append("{\"Format\": \"Incremental\", ");
    add_mdHeaderToJson();
    outBuffer.append(", \"IncrementalHeader\": {");
    outBuffer.append(incHeader.print());
    outBuffer.append("}, \"Payload\": [");
}

void UdpParser::add_snapHeaderToJson()
{
    outBuffer.append("{\"Format\": \"Snapshot\", ");
    add_mdHeaderToJson();
    outBuffer.append(", \"Payload\": [");
}

void UdpParser::add_incMsgToJson(const std::string& s)
{
    if (msgCapdCount)
        outBuffer.append(", ");
   
    outBuffer.append("{\"SBEMessageHeader\": {");
    outBuffer.append(sbeHeader.print());
    outBuffer.append("}, \"SBEMessageRoot\": {");
    outBuffer.append(s);
    outBuffer.append("}}");
    msgCapdCount++;
}

void UdpParser::add_snapRootMsgToJson(const std::string& s)
{
    outBuffer.append("\"SBEMessageHeader\": {");
    outBuffer.append(sbeHeader.print());
    outBuffer.append("}, \"SBEMessageRoot\": {");
    outBuffer.append(s);
    outBuffer.append("}");
}

void UdpParser::add_snapSizeMsgToJson(const std::string& s)
{
    msgCapdCount = 0;
    outBuffer.append(", \"GroupSize\": {");
    outBuffer.append(s);
    outBuffer.append("}, \"RepeatingSection\": ");
}

void UdpParser::add_snapGroupMsgToJson(const std::string& s)
{
    if (msgCapdCount)
        outBuffer.append(", ");
    
    outBuffer.append("{");
    outBuffer.append(s);
    outBuffer.append("}");
    msgCapdCount++;
}

void UdpParser::begin_arrToJson()
{
    outBuffer.append("[");
}

void UdpParser::begin_objToJson()
{
    outBuffer.append("{");
}

void UdpParser::end_arrToJson()
{
    outBuffer.append("]");
}

void UdpParser::end_objToJson()
{
    outBuffer.append("}");
}

void UdpParser::send_msgToJson()
{
    outBuffer.append("]}}\n");
    output_->write(outBuffer.c_str(), outBuffer.size());
}
