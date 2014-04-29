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

#ifndef __INET_RADIOCHANNEL_H_
#define __INET_RADIOCHANNEL_H_

#include <vector>
#include <algorithm>
#include "IRadioChannel.h"
#include "IRadioSignalArrival.h"
#include "IRadioSignalPropagation.h"
#include "IRadioSignalAttenuation.h"
#include "IRadioBackgroundNoise.h"

class INET_API RadioChannel : public cSimpleModule, public IRadioChannel
{
    protected:
        /**
         * The intermediate computation results related to a transmission and a
         * receiver radio.
         */
        class CacheEntry
        {
            public:
                const IRadioSignalArrival *arrival;
                const IRadioSignalReception *reception;
                const IRadioSignalReceptionDecision *decision;

            public:
                CacheEntry() :
                    arrival(NULL),
                    reception(NULL),
                    decision(NULL)
                {}
        };

    protected:
        /** @name Parameters that control the behavior of the radio channel. */
        //@{
        /**
         * The propagation model of transmissions.
         */
        const IRadioSignalPropagation *propagation;
        /**
         * The attenuation model of transmissions.
         */
        const IRadioSignalAttenuation *attenuation;
        /**
         * The radio channel background noise model.
         */
        const IRadioBackgroundNoise *backgroundNoise;
        /**
         * The minimum time needed to consider two transmissions interfering.
         */
        // TODO: compute from longest frame duration, maximum mobility speed and signal propagation time
        simtime_t minInterferenceTime;
        /**
         * The maximum transmission duration of a radio signal.
         */
        simtime_t maxTransmissionDuration;
        /**
         * The maximum communication range where a transmission can still be
         * potentially successfully received.
         */
        m maxCommunicationRange;
        /**
         * The maximum interference range where a transmission has still some
         * effect on other transmissions.
         */
        m maxInterferenceRange;
        //@}

        /** @name State */
        //@{
        /**
         * The list of radios that transmit and receive radio signals on the
         * radio channel.
         */
        std::vector<const IRadio *> radios;
        /**
         * The list of ongoing transmissions on the radio channel.
         */
        std::vector<const IRadioSignalTransmission *> transmissions;
        //@}

        /** @name Cache */
        //@{
        /**
         * The smallest transmission id of all ongoing transmissions.
         */
        int baseTransmissionId;
        /**
         * Caches pre-computed radio signal information for transmissions and
         * radios. The outer vector is indexed by transmission id (offset with
         * base transmission id) and the inner vector is indexed by radio id.
         * Values that are no longer needed are removed from the beginning only.
         * May contain NULL values for not yet pre-computed information.
         */
        mutable std::vector<std::vector<CacheEntry> *> cache;
        /**
         * Last time non-interfering transmissions were removed.
         */
        simtime_t lastRemoveNonInterferingTransmissions;
        //@}

        /** @name Statistics */
        //@{
        /**
         * Total number of transmissions.
         */
        mutable long transmissionCount;
        /**
         * Total number of reception computations.
         */
        mutable long receptionComputationCount;
        /**
         * Total number of reception decision computations.
         */
        mutable long receptionDecisionComputationCount;
        /**
         * Total number of listening decision computations.
         */
        mutable long listeningDecisionComputationCount;
        /**
         * Total number of radio signal reception cache queries.
         */
        mutable long cacheReceptionGetCount;
        /**
         * Total number of radio signal reception cache hits.
         */
        mutable long cacheReceptionHitCount;
        /**
         * Total number of radio signal reception decision cache queries.
         */
        mutable long cacheDecisionGetCount;
        /**
         * Total number of radio signal reception decision cache hits.
         */
        mutable long cacheDecisionHitCount;
        //@}

    protected:
        virtual int numInitStages() const { return NUM_INIT_STAGES; }
        virtual void initialize(int stage);
        virtual void finish();

        virtual CacheEntry *getCacheEntry(const IRadio *radio, const IRadioSignalTransmission *transmission) const;

        virtual const IRadioSignalArrival *getCachedArrival(const IRadio *radio, const IRadioSignalTransmission *transmission) const;
        virtual void setCachedArrival(const IRadio *radio, const IRadioSignalTransmission *transmission, const IRadioSignalArrival *arrival) const;
        virtual void removeCachedArrival(const IRadio *radio, const IRadioSignalTransmission *transmission) const;

        virtual const IRadioSignalReception *getCachedReception(const IRadio *radio, const IRadioSignalTransmission *transmission) const;
        virtual void setCachedReception(const IRadio *radio, const IRadioSignalTransmission *transmission, const IRadioSignalReception *reception) const;
        virtual void removeCachedReception(const IRadio *radio, const IRadioSignalTransmission *transmission) const;

        virtual const IRadioSignalReceptionDecision *getCachedDecision(const IRadio *radio, const IRadioSignalTransmission *transmission) const;
        virtual void setCachedDecision(const IRadio *radio, const IRadioSignalTransmission *transmission, const IRadioSignalReceptionDecision *decision) const;
        virtual void removeCachedDecision(const IRadio *radio, const IRadioSignalTransmission *transmission) const;

        virtual void invalidateCachedDecisions(const IRadioSignalTransmission *transmission);
        virtual void invalidateCachedDecision(const IRadioSignalReceptionDecision *decision);

        // TODO: virtual W computeMaxTransmissionPower() const = 0;
        // TODO: virtual W computeMinReceptionPower() const = 0;

        virtual const simtime_t computeMinInterferenceTime() const;
        virtual const simtime_t computeMaxTransmissionDuration() const;

        virtual m computeMaxRange(W maxPower, W minPower) const;
        virtual m computeMaxCommunicationRange() const;
        virtual m computeMaxInterferenceRange() const;

        virtual bool isInCommunicationRange(const IRadioSignalTransmission *transmission, const Coord startPosition, const Coord endPosition) const;
        virtual bool isInInterferenceRange(const IRadioSignalTransmission *transmission, const Coord startPosition, const Coord endPosition) const;

        virtual bool isInterferingTransmission(const IRadioSignalTransmission *transmission, const IRadioSignalListening *listening) const;
        virtual bool isInterferingTransmission(const IRadioSignalTransmission *transmission, const IRadioSignalReception *reception) const;

        virtual void removeNonInterferingTransmissions();
        virtual void removeNonInterferingTransmission(const IRadioSignalTransmission *transmission) {}

        virtual const IRadioSignalReception *computeReception(const IRadio *radio, const IRadioSignalTransmission *transmission) const;
        virtual const std::vector<const IRadioSignalReception *> *computeInterferingReceptions(const IRadioSignalListening *listening, const std::vector<const IRadioSignalTransmission *> *transmissions) const;
        virtual const std::vector<const IRadioSignalReception *> *computeInterferingReceptions(const IRadioSignalReception *reception, const std::vector<const IRadioSignalTransmission *> *transmissions) const;
        virtual const IRadioSignalReceptionDecision *computeReceptionDecision(const IRadio *radio, const IRadioSignalListening *listening, const IRadioSignalTransmission *transmission, const std::vector<const IRadioSignalTransmission *> *transmissions) const;
        virtual const IRadioSignalListeningDecision *computeListeningDecision(const IRadio *radio, const IRadioSignalListening *listening, const std::vector<const IRadioSignalTransmission *> *transmissions) const;

        virtual const IRadioSignalReception *getReception(const IRadio *radio, const IRadioSignalTransmission *transmission) const;
        virtual const IRadioSignalReceptionDecision *getReceptionDecision(const IRadio *radio, const IRadioSignalListening *listening, const IRadioSignalTransmission *transmission) const;

    public:
        RadioChannel();
        RadioChannel(const IRadioSignalPropagation *propagation, const IRadioSignalAttenuation *attenuation, const IRadioBackgroundNoise *backgroundNoise, const simtime_t minInterferenceTime, const simtime_t maxTransmissionDuration, m maxCommunicationRange, m maxInterferenceRange);
        virtual ~RadioChannel();

        virtual const IRadioSignalPropagation *getPropagation() const { return propagation; }
        virtual const IRadioSignalAttenuation *getAttenuation() const { return attenuation; }
        virtual const IRadioBackgroundNoise *getBackgroundNoise() const { return backgroundNoise; }

        virtual void addRadio(const IRadio *radio);
        virtual void removeRadio(const IRadio *radio);

        virtual void transmitToChannel(const IRadio *radio, const IRadioSignalTransmission *transmission);
        virtual void sendToChannel(IRadio *radio, const IRadioFrame *frame);

        virtual const IRadioSignalReceptionDecision *receiveFromChannel(const IRadio *radio, const IRadioSignalListening *listening, const IRadioSignalTransmission *transmission) const;
        virtual const IRadioSignalListeningDecision *listenOnChannel(const IRadio *radio, const IRadioSignalListening *listening) const;

        virtual bool isPotentialReceiver(const IRadio *radio, const IRadioSignalTransmission *transmission) const;
        virtual bool isReceptionAttempted(const IRadio *radio, const IRadioSignalTransmission *transmission) const;

        virtual const IRadioSignalArrival *getArrival(const IRadio *radio, const IRadioSignalTransmission *transmission) const;
        // KLUDGE: to keep fingerprint
        virtual void setArrival(const IRadio *radio, const IRadioSignalTransmission *transmission, const IRadioSignalArrival *arrival);
};

#endif
