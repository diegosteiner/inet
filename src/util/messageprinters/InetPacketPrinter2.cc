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
#include "INetworkDatagram.h"
#include "IPv4Datagram.h"
#include "PingPayload_m.h"
#include "RIPPacket_m.h"
#include "TCPSegment.h"
#include "UDPPacket.h"

//TODO HACK, remove next line
#include "cmessageprinter.h"

class INET_API InetPacketPrinter2 : public cMessagePrinter
{
    protected:
        mutable bool enabled;
    protected:
        std::string formatARPPacket(ARPPacket *packet) const;
        std::string formatICMPPacket(Address srcAddr, Address destAddr, ICMPMessage *packet) const;
        std::string formatPingPayload(Address srcAddr, Address destAddr, PingPayload *packet) const;
        std::string formatRIPPacket(RIPPacket *packet) const;
        std::string formatTCPPacket(Address srcAddr, Address destAddr, TCPSegment *tcpSeg) const;
        std::string formatUDPPacket(Address srcAddr, Address destAddr, UDPPacket *udpPacket) const;
    public:
        InetPacketPrinter2() { enabled = true; }
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
    Address srcAddr, destAddr;

    enabled = true;
    for (cPacket *pk = dynamic_cast<cPacket *>(msg); enabled && pk; pk = pk->getEncapsulatedPacket()) {
        std::ostringstream out;
        if (dynamic_cast<INetworkDatagram *>(pk)) {
            INetworkDatagram *dgram = dynamic_cast<INetworkDatagram *>(pk);
            srcAddr = dgram->getSourceAddress();
            destAddr = dgram->getDestinationAddress();
            out << pk->getClassName() << ": " << srcAddr << " > " << destAddr;
            if (dynamic_cast<IPv4Datagram *>(pk)) {
                IPv4Datagram *ipv4dgram = static_cast<IPv4Datagram *>(pk);
                if (ipv4dgram->getMoreFragments() || ipv4dgram->getFragmentOffset() > 0) {
                    out << " " << (ipv4dgram->getMoreFragments() ? "" : "last ")
                        << "fragment with offset=" << ipv4dgram->getFragmentOffset() << " of ";
                }
            }
        }
        else if (dynamic_cast<EtherFrame *>(pk)) {
            EtherFrame *eth = static_cast<EtherFrame *>(pk);
            out << "ETH: " << eth->getSrc() << " > " << eth->getDest() << " (" << eth->getByteLength() << " bytes)";
        }
        else if (dynamic_cast<TCPSegment *>(pk)) {
            out << formatTCPPacket(srcAddr, destAddr, static_cast<TCPSegment *>(pk));
        }
        else if (dynamic_cast<UDPPacket *>(pk)) {
            out << formatUDPPacket(srcAddr, destAddr, static_cast<UDPPacket *>(pk));
        }
        else if (dynamic_cast<ICMPMessage *>(pk)) {
            out << formatICMPPacket(srcAddr, destAddr, static_cast<ICMPMessage *>(pk));
        }
        else if (dynamic_cast<PingPayload *>(pk)) {
            out << formatPingPayload(srcAddr, destAddr, static_cast<PingPayload *>(pk));
        }
        else if (dynamic_cast<ARPPacket *>(pk)) {
            out << formatARPPacket(static_cast<ARPPacket *>(pk));
        }
        else if (dynamic_cast<RIPPacket *>(pk)) {
            out << formatRIPPacket(static_cast<RIPPacket *>(pk));
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
        case ARP_REQUEST: os << "ARP req:"; break;
        case ARP_REPLY: os << "ARP reply:"; break;
        case ARP_RARP_REQUEST: os << "RARP req:"; break;
        case ARP_RARP_REPLY: os << "RARP reply:"; break;
        default: os << "ARP ???:"; break;
    }
    os << " d=" << packet->getDestIPAddress()
       << "(" << packet->getDestMACAddress()
       << ") s=" << packet->getSrcIPAddress()
       << "(" << packet->getSrcMACAddress() << ")";
    return os.str();
}

std::string InetPacketPrinter2::formatTCPPacket(Address srcAddr, Address destAddr, TCPSegment *tcpSeg) const
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

std::string InetPacketPrinter2::formatUDPPacket(Address srcAddr, Address destAddr, UDPPacket *udpPacket) const
{
    std::ostringstream os;
    os << "UDP: " << srcAddr << '.' << udpPacket->getSourcePort() << " > " << destAddr << '.' << udpPacket->getDestinationPort()
       << ": (" << udpPacket->getByteLength() << ")";
    return os.str();
}

std::string InetPacketPrinter2::formatPingPayload(Address srcAddr, Address destAddr, PingPayload *packet) const
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

std::string InetPacketPrinter2::formatICMPPacket(Address srcAddr, Address destAddr, ICMPMessage *packet) const
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
            enabled = false; // stop printing
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

