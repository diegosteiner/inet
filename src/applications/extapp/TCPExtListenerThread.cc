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

#include "SocketsRTScheduler.h"

class TCPExtActiveThread
{
  protected:
    int extSocketId;
    cModule *appModule;
    SocketsRTScheduler *rtScheduler;
    TCPSocket inetSocket;
  public:
    TCPExtActiveThread();
    virtual ~TCPExtActiveThread();
    virtual void init(cModule *appModule); // called in INITSTAGE_APPLICATION_LAYER
    virtual void handleMessage(cMessage *msg);
};

class TCPExtListenerThread
{
  protected:
    int extListenerSocketId;
    cModule *appModule;
    SocketsRTScheduler *rtScheduler;
  public:
    TCPExtListenerThread();
    virtual ~TCPExtListenerThread();
    virtual void init(cModule *appModule); // called in INITSTAGE_APPLICATION_LAYER
    virtual void handleMessage(cMessage *msg);
    virtual void acceptExtConnection(cMessage *msg);
};

TCPExtListenerThread::TCPExtListenerThread()
{
    extListenerSocketId = INVALID_SOCKET;
    appModule = NULL;
    rtScheduler = NULL;
}

TCPExtListenerThread::~TCPExtListenerThread()
{
}

void TCPExtListenerThread::init(cModule *appModulePar) // called in INITSTAGE_APPLICATION_LAYER
{
    appModule = appModulePar;
    rtScheduler = check_and_cast<SocketsRTScheduler *>(simulation.getScheduler());

    extListenerSocketId = socket(AF_INET, SOCK_STREAM, 0);
    if (extListenerSocketId == INVALID_SOCKET)
        throw cRuntimeError("cannot create socket");

    sockaddr_in sinInterface;
    sinInterface.sin_family = AF_INET;
    sinInterface.sin_addr.s_addr = INADDR_ANY;
    sinInterface.sin_port = htons(uint16_t(appModule->par("tunnelPort")));
    if (bind(extListenerSocketId, (sockaddr*) &sinInterface, sizeof(sockaddr_in)) == SOCKET_ERROR)
        throw cRuntimeError("socket bind() failed");

    listen(extListenerSocketId, SOMAXCONN);

    rtScheduler->addSocket(appModule, this, extListenerSocketId, true);
}

void TCPExtListenerThread::handleMessage(cMessage *msg)
{
    switch(msg->getKind())
    {
        case SocketsRTScheduler::DATA:
            throw cRuntimeError("DATA not accepted");
            delete msg;
            break;
        case SocketsRTScheduler::CLOSED:
            if (extListenerSocketId != msg->par("fd").longValue())
                throw cRuntimeError("unknown socket id");
            close();
            extListenerSocketId = INVALID_SOCKET;
            delete msg;
            break;
        case SocketsRTScheduler::ACCEPT:
            acceptExtConnection(msg);
            if (extListenerSocketId != INVALID_SOCKET)
                throw cRuntimeError("socket already opened");
             = msg->par("fd").longValue();
            rtScheduler->addSocket(this, connSocket, false);
            connect();
            delete msg;
            break;
    }
}

void TCPExtListenerThread::acceptExtConnection(cMessage *msg)
{
    TCPExtActiveThread *thread = new TCPExtActiveThread();
    thread->init(appModule);
}

void TCPExtActiveThread::handleMessage(cMessage *msg)
{
    switch(msg->getKind())
    {
        case SocketsRTScheduler::DATA:
            throw cRuntimeError("DATA not accepted");
            delete msg;
            break;
        case SocketsRTScheduler::CLOSED:
            if (extSocketId != msg->par("fd").longValue())
                throw cRuntimeError("unknown socket id");
            close();
            extSocketId = INVALID_SOCKET;
            delete msg;
            break;
        case SocketsRTScheduler::ACCEPT:
            throw cRuntimeError("socket already opened");
            delete msg;
            break;
    }
}

