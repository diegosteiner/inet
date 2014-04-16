//
// Copyright (C) 2013 OpenSim Ltd.
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

#ifndef __INET_IEEE80211RADIOCHANNEL_H_
#define __INET_IEEE80211RADIOCHANNEL_H_

#include "NewRadioChannel.h"

class INET_API Ieee80211RadioChannel : public NewRadioChannel
{
    protected:
        int numChannels;

    protected:
        virtual void initialize(int stage);

    public:
        Ieee80211RadioChannel() :
            NewRadioChannel(),
            numChannels(-1)
        {}

        Ieee80211RadioChannel(const IRadioSignalPropagation *propagation, const IRadioSignalAttenuation *attenuation, const IRadioBackgroundNoise *backgroundNoise, int numChannels) :
            NewRadioChannel(propagation, attenuation, backgroundNoise),
            numChannels(numChannels)
        {}

        virtual int getNumChannels() const { return numChannels; }
};

#endif
