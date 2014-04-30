//
// Copyright (C) 2014 OpenSim Ltd.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//


#include "INETDefs.h"

#include "Address.h"
#include "ARPPacket_m.h"
#include "EtherFrame.h"
#include "ICMPMessage.h"
#include "Ieee80211Frame_m.h"
#include "INetworkDatagram.h"
#include "IPv4Datagram.h"
#include "PingPayload_m.h"
#include "RIPPacket_m.h"
#include "SimplifiedRadioFrame.h"
#include "TCPSegment.h"
#include "UDPPacket.h"

//TODO HACK, remove next line
#include "cmessageprinter.h"

class INET_API InetPacketPrinter2 : public cMessagePrinter
{
    protected:
        mutable bool showEncapsulatedPackets;
        mutable Address srcAddr;
        mutable Address destAddr;
    protected:
        std::string formatARPPacket(ARPPacket *packet) const;
        std::string formatICMPPacket(ICMPMessage *packet) const;
        std::string formatIeee80211Frame(Ieee80211Frame *packet) const;
        std::string formatPingPayload(PingPayload *packet) const;
        std::string formatRIPPacket(RIPPacket *packet) const;
        std::string formatSimplifiedRadioFrame(SimplifiedRadioFrame *packet) const;
        std::string formatTCPPacket(TCPSegment *tcpSeg) const;
        std::string formatUDPPacket(UDPPacket *udpPacket) const;
    public:
        InetPacketPrinter2() { showEncapsulatedPackets = true; }
        virtual ~InetPacketPrinter2() {}
        virtual int getScoreFor(cMessage *msg) const;
        virtual void printMessage(std::ostream& os, cMessage *msg) const;
};

Register_MessagePrinter(InetPacketPrinter2);

int InetPacketPrinter2::getScoreFor(cMessage *msg) const
{
    return msg->isPacket() ? 21 : 0;
}

void InetPacketPrinter2::printMessage(std::ostream& os, cMessage *msg) const
{
    std::string outs;

    //reset mutable variables
    srcAddr = destAddr = Address();
    showEncapsulatedPackets = true;

    for (cPacket *pk = dynamic_cast<cPacket *>(msg); showEncapsulatedPackets && pk; pk = pk->getEncapsulatedPacket()) {
        std::ostringstream out;
        if (dynamic_cast<INetworkDatagram *>(pk)) {
            INetworkDatagram *dgram = dynamic_cast<INetworkDatagram *>(pk);
            srcAddr = dgram->getSourceAddress();
            destAddr = dgram->getDestinationAddress();
            if (dynamic_cast<IPv4Datagram *>(pk)) {
                IPv4Datagram *ipv4dgram = static_cast<IPv4Datagram *>(pk);
                out << "IPv4: " << srcAddr << " > " << destAddr;
                if (ipv4dgram->getMoreFragments() || ipv4dgram->getFragmentOffset() > 0) {
                    out << " " << (ipv4dgram->getMoreFragments() ? "" : "last ")
                        << "fragment with offset=" << ipv4dgram->getFragmentOffset() << " of ";
                }
            }
            else
                out << pk->getClassName() << ": " << srcAddr << " > " << destAddr;
        }
        else if (dynamic_cast<EtherFrame *>(pk)) {
            EtherFrame *eth = static_cast<EtherFrame *>(pk);
            out << "ETH: " << eth->getSrc() << " > " << eth->getDest() << " (" << eth->getByteLength() << " bytes)";
        }
        else if (dynamic_cast<TCPSegment *>(pk)) {
            out << formatTCPPacket(static_cast<TCPSegment *>(pk));
        }
        else if (dynamic_cast<UDPPacket *>(pk)) {
            out << formatUDPPacket(static_cast<UDPPacket *>(pk));
        }
        else if (dynamic_cast<ICMPMessage *>(pk)) {
            out << formatICMPPacket(static_cast<ICMPMessage *>(pk));
        }
        else if (dynamic_cast<Ieee80211Frame *>(pk)) {
            out << formatIeee80211Frame(static_cast<Ieee80211Frame *>(pk));
        }
        else if (dynamic_cast<PingPayload *>(pk)) {
            out << formatPingPayload(static_cast<PingPayload *>(pk));
        }
        else if (dynamic_cast<ARPPacket *>(pk)) {
            out << formatARPPacket(static_cast<ARPPacket *>(pk));
        }
        else if (dynamic_cast<RIPPacket *>(pk)) {
            out << formatRIPPacket(static_cast<RIPPacket *>(pk));
        }
        else if (dynamic_cast<SimplifiedRadioFrame *>(pk)) {
            out << formatSimplifiedRadioFrame(static_cast<SimplifiedRadioFrame *>(pk));
        }
        else
            out << pk->getClassName() <<":" << pk->getByteLength() << " bytes";
        if (outs.length())
            out << "  \t" << outs;
        outs = out.str();
    }
    os << outs;
}

std::string InetPacketPrinter2::formatARPPacket(ARPPacket *packet) const
{
    std::ostringstream os;
    switch (packet->getOpcode()) {
        case ARP_REQUEST:
            os << "ARP req: " << packet->getDestIPAddress()
               << "=? (s=" << packet->getSrcIPAddress() << "(" << packet->getSrcMACAddress() << "))";
            break;
        case ARP_REPLY:
            os << "ARP reply: "
            << packet->getSrcIPAddress() << "=" << packet->getSrcMACAddress()
            << " (d=" << packet->getDestIPAddress() << "(" << packet->getDestMACAddress() << "))"
            ;
            break;
        case ARP_RARP_REQUEST:
            os << "RARP req: " << packet->getDestMACAddress()
               << "=? (s=" << packet->getSrcIPAddress() << "(" << packet->getSrcMACAddress() << "))";
            break;
        case ARP_RARP_REPLY:
            os << "RARP reply: "
               << packet->getSrcMACAddress() << "=" << packet->getSrcIPAddress()
               << " (d=" << packet->getDestIPAddress() << "(" << packet->getDestMACAddress() << "))";
            break;
        default:
            os << "ARP op=" << packet->getOpcode() << ": d=" << packet->getDestIPAddress()
               << "(" << packet->getDestMACAddress()
               << ") s=" << packet->getSrcIPAddress()
               << "(" << packet->getSrcMACAddress() << ")";
            break;
    }
    return os.str();
}

std::string InetPacketPrinter2::formatIeee80211Frame(Ieee80211Frame *packet) const
{
    std::ostringstream os;

    os << "WLAN ";
    switch (packet->getType()) {
        case ST_ASSOCIATIONREQUEST:
            os << " assoc req";     //TODO
            break;
        case ST_ASSOCIATIONRESPONSE:
            os << " assoc resp";     //TODO
            break;
        case ST_REASSOCIATIONREQUEST:
            os << " reassoc req";     //TODO
            break;
        case ST_REASSOCIATIONRESPONSE:
            os << " reassoc resp";     //TODO
            break;
        case ST_PROBEREQUEST:
            os << " probe request";     //TODO
            break;
        case ST_PROBERESPONSE:
            os << " probe response";     //TODO
            break;
        case ST_BEACON:
            os << "beacon";     //TODO
            break;
        case ST_ATIM:
            os << " atim";     //TODO
            break;
        case ST_DISASSOCIATION:
            os << " disassoc";     //TODO
            break;
        case ST_AUTHENTICATION:
            os << " auth";     //TODO
            break;
        case ST_DEAUTHENTICATION:
            os << " deauth";     //TODO
            break;
        case ST_ACTION:
            os << " action";     //TODO
            break;
        case ST_NOACKACTION:
            os << " noackaction";     //TODO
            break;
        case ST_PSPOLL:
            os << " pspoll";     //TODO
            break;
        case ST_RTS:
        {
            Ieee80211RTSFrame *pk = check_and_cast<Ieee80211RTSFrame *>(packet);
            os << " rts " << pk->getTransmitterAddress() << " to " << packet->getReceiverAddress();
            break;
        }
        case ST_CTS:
            os << " cts " << packet->getReceiverAddress();
            break;
        case ST_ACK:
            os << " ack " << packet->getReceiverAddress();
            break;
        case ST_BLOCKACK_REQ:
            os << " reassoc resp";     //TODO
            break;
        case ST_BLOCKACK:
            os << " block ack";     //TODO
            break;
        case ST_DATA:
            os << " data";     //TODO
            break;
        case ST_LBMS_REQUEST:
            os << " lbms req";     //TODO
            break;
        case ST_LBMS_REPORT:
            os << " lbms report";     //TODO
            break;
        default:
            os << "??? (" << packet->getClassName() << ")";
            break;
    }
    return os.str();
}

std::string InetPacketPrinter2::formatTCPPacket(TCPSegment *tcpSeg) const
{
    std::ostringstream os;
    os << "TCP: " << srcAddr << '.' << tcpSeg->getSrcPort() << " > " << destAddr << '.' << tcpSeg->getDestPort() << ":";
    // flags
    bool flags = false;
    if (tcpSeg->getUrgBit()) { flags = true; os << " U"; }
    if (tcpSeg->getAckBit()) { flags = true; os << " A"; }
    if (tcpSeg->getPshBit()) { flags = true; os << " P"; }
    if (tcpSeg->getRstBit()) { flags = true; os << " R"; }
    if (tcpSeg->getSynBit()) { flags = true; os << " S"; }
    if (tcpSeg->getFinBit()) { flags = true; os << " F"; }
    if (!flags) { os << " ."; }

    // data-seqno
    if (tcpSeg->getPayloadLength()>0 || tcpSeg->getSynBit())
    {
        os << " " << tcpSeg->getSequenceNo() << ":" << tcpSeg->getSequenceNo()+tcpSeg->getPayloadLength();
        os << "(" << tcpSeg->getPayloadLength() << ")";
    }

    // ack
    if (tcpSeg->getAckBit())
        os << " ack " << tcpSeg->getAckNo();

    // window
    os << " win " << tcpSeg->getWindow();

    // urgent
    if (tcpSeg->getUrgBit())
        os << " urg " << tcpSeg->getUrgentPointer();
    return os.str();
}

std::string InetPacketPrinter2::formatUDPPacket(UDPPacket *udpPacket) const
{
    std::ostringstream os;
    os << "UDP: " << srcAddr << '.' << udpPacket->getSourcePort() << " > " << destAddr << '.' << udpPacket->getDestinationPort()
       << ": (" << udpPacket->getByteLength() << ")";
    return os.str();
}

std::string InetPacketPrinter2::formatPingPayload(PingPayload *packet) const
{
    std::ostringstream os;
    ICMPMessage *owner = dynamic_cast<ICMPMessage *>(packet->getOwner());

    os << "PING ";
    if (owner) {
        switch(owner->getType()) {
            case ICMP_ECHO_REQUEST: os << "req "; break;
            case ICMP_ECHO_REPLY: os << "reply "; break;
            default: break;
        }
    }
    os << srcAddr << " to " << destAddr
       << " (" << packet->getByteLength() << " bytes) id=" << packet->getId()
       << " seq=" << packet->getSeqNo();

    return os.str();
}

std::string InetPacketPrinter2::formatICMPPacket(ICMPMessage *packet) const
{
    std::ostringstream os;
    switch (packet->getType()) {
        case ICMP_ECHO_REQUEST:
            os << "ICMP echo request " << srcAddr << " to " << destAddr;
            break;
        case ICMP_ECHO_REPLY:
            os << "ICMP echo reply " << srcAddr << " to " << destAddr;
            break;
        case ICMP_DESTINATION_UNREACHABLE:
            os << "ICMP dest unreachable " << srcAddr << " to " << destAddr << " type=" << packet->getType() << " code=" << packet->getCode()
               << " origin:  \t";
            InetPacketPrinter2().printMessage(os, packet->getEncapsulatedPacket());
            showEncapsulatedPackets = false; // stop printing
            break;
        default:
            os << "ICMP " << srcAddr << " to " << destAddr << " type=" << packet->getType() << " code=" << packet->getCode();
            break;
    }
    return os.str();
}

std::string InetPacketPrinter2::formatRIPPacket(RIPPacket *packet) const
{
    std::ostringstream os;

    os << "RIP: ";
    switch(packet->getCommand()) {
        case RIP_REQUEST:  os << "req "; break;
        case RIP_RESPONSE: os << "resp "; break;
        default: os << "unknown "; break;
    }
    unsigned int size = packet->getEntryArraySize();
    for (unsigned int i = 0; i < size; ++i) {
        RIPEntry &entry = packet->getEntry(i);
        if (i > 0)
            os << "; ";
        if (i > 2) {
            os << "...(" << size << " entries)";
            break;
        }
        os << entry.address << "/" << entry.prefixLength;
        if (!entry.nextHop.isUnspecified())
            os << "->" << entry.nextHop;
        if (entry.metric == 16)
            os << " unroutable";
        else
        os << " m=" << entry.metric;
    }
    return os.str();
}

std::string InetPacketPrinter2::formatSimplifiedRadioFrame(SimplifiedRadioFrame *packet) const
{
    std::ostringstream os;

    os << "RADIO from " << packet->getSenderPos() << " on " << packet->getCarrierFrequency()/1e6
       << "MHz, ch=" << packet->getChannelNumber() << ", duration=" << SIMTIME_DBL(packet->getDuration())*1000 << "ms";
    return os.str();
}

