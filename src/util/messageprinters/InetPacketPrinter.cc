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
#include "ICMPMessage.h"
#include "INetworkDatagram.h"
#include "IPv4Datagram.h"
#include "PingPayload_m.h"
#include "TCPSegment.h"
#include "UDPPacket.h"

//TODO HACK, remove next line
#include "cmessageprinter.h"

class INET_API InetPacketPrinter : public cMessagePrinter
{
    protected:
        void printTCPPacket(std::ostream& os, Address srcAddr, Address destAddr, TCPSegment *tcpSeg) const;
        void printUDPPacket(std::ostream& os, Address srcAddr, Address destAddr, UDPPacket *udpPacket) const;
        void printICMPPacket(std::ostream& os, Address srcAddr, Address destAddr, ICMPMessage *packet) const;
    public:
        InetPacketPrinter() {}
        virtual ~InetPacketPrinter() {}
        virtual int getScoreFor(cMessage *msg) const;
        virtual void printMessage(std::ostream& os, cMessage *msg) const;
};

Register_MessagePrinter(InetPacketPrinter);

int InetPacketPrinter::getScoreFor(cMessage *msg) const
{
    return msg->isPacket() ? 20 : 0;
}

void InetPacketPrinter::printMessage(std::ostream& os, cMessage *msg) const
{
    Address srcAddr, destAddr;

    for (cPacket *pk = dynamic_cast<cPacket *>(msg); pk; pk = pk->getEncapsulatedPacket()) {
        if (dynamic_cast<INetworkDatagram *>(pk)) {
            INetworkDatagram *dgram = dynamic_cast<INetworkDatagram *>(pk);
            srcAddr = dgram->getSourceAddress();
            destAddr = dgram->getDestinationAddress();
            if (dynamic_cast<IPv4Datagram *>(pk))
            {
                IPv4Datagram *ipv4dgram = static_cast<IPv4Datagram *>(pk);
                if (ipv4dgram->getMoreFragments() || ipv4dgram->getFragmentOffset() > 0)
                    os << (ipv4dgram->getMoreFragments() ? "" : "last ")
                       << "fragment with offset=" << ipv4dgram->getFragmentOffset() << " of ";
            }
        }
        else if (dynamic_cast<TCPSegment *>(pk)) {
            printTCPPacket(os, srcAddr, destAddr, static_cast<TCPSegment *>(pk));
            return;
        }
        else if (dynamic_cast<UDPPacket *>(pk)) {
            printUDPPacket(os, srcAddr, destAddr, static_cast<UDPPacket *>(pk));
            return;
        }
        else if (dynamic_cast<ICMPMessage *>(pk)) {
            printICMPPacket(os, srcAddr, destAddr, static_cast<ICMPMessage *>(pk));
            return;
        }
    }
    os << "(" << msg->getClassName() << ")" << " id=" << msg->getId() << " kind=" << msg->getKind();
}

void InetPacketPrinter::printTCPPacket(std::ostream& os, Address srcAddr, Address destAddr, TCPSegment *tcpSeg) const
{
    os << " TCP: " << srcAddr << '.' << tcpSeg->getSrcPort() << " > " << destAddr << '.' << tcpSeg->getDestPort() << ": ";
    // flags
    bool flags = false;
    if (tcpSeg->getUrgBit()) { flags = true; os << "U "; }
    if (tcpSeg->getAckBit()) { flags = true; os << "A "; }
    if (tcpSeg->getPshBit()) { flags = true; os << "P "; }
    if (tcpSeg->getRstBit()) { flags = true; os << "R "; }
    if (tcpSeg->getSynBit()) { flags = true; os << "S "; }
    if (tcpSeg->getFinBit()) { flags = true; os << "F "; }
    if (!flags) { os << ". "; }

    // data-seqno
    if (tcpSeg->getPayloadLength()>0 || tcpSeg->getSynBit())
    {
        os << tcpSeg->getSequenceNo() << ":" << tcpSeg->getSequenceNo()+tcpSeg->getPayloadLength();
        os << "(" << tcpSeg->getPayloadLength() << ") ";
    }

    // ack
    if (tcpSeg->getAckBit())
        os << "ack " << tcpSeg->getAckNo() << " ";

    // window
    os << "win " << tcpSeg->getWindow() << " ";

    // urgent
    if (tcpSeg->getUrgBit())
        os << "urg " << tcpSeg->getUrgentPointer() << " ";
}

void InetPacketPrinter::printUDPPacket(std::ostream& os, Address srcAddr, Address destAddr, UDPPacket *udpPacket) const
{
    os << " UDP: " << srcAddr << '.' << udpPacket->getSourcePort() << " > " << destAddr << '.' << udpPacket->getDestinationPort()
       << ": (" << udpPacket->getByteLength() << ")";
}

void InetPacketPrinter::printICMPPacket(std::ostream& os, Address srcAddr, Address destAddr, ICMPMessage *packet) const
{
    switch (packet->getType()) {
        case ICMP_ECHO_REQUEST:
        {
            PingPayload *payload = check_and_cast<PingPayload *>(packet->getEncapsulatedPacket());
            os << "ping " << srcAddr << " to " << destAddr
               << " (" << packet->getByteLength() << " bytes) id=" << payload->getId() << " seq=" <<payload->getSeqNo();
            break;
        }
        case ICMP_ECHO_REPLY:
        {
            PingPayload *payload = check_and_cast<PingPayload *>(packet->getEncapsulatedPacket());
            os << "pong " << srcAddr << " to " << destAddr
               << " (" << packet->getByteLength() << " bytes) id=" << payload->getId() << " seq=" <<payload->getSeqNo();
            break;
        }
        case ICMP_DESTINATION_UNREACHABLE:
            os << "ICMP dest unreachable " << srcAddr << " to " << destAddr << " type=" << packet->getType() << " code=" << packet->getCode()
               << " origin: ";
            printMessage(os, packet->getEncapsulatedPacket());
            break;
        default:
            os << "ICMP " << srcAddr << " to " << destAddr << " type=" << packet->getType() << " code=" << packet->getCode();
            break;
    }
}

