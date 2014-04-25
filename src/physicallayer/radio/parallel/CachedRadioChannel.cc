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

#include <CachedRadioChannel.h>

void CachedRadioChannel::finish()
{
    double receptionCacheHitPercentage = 100 * (double)receptionCacheHitCount / (double)receptionCacheGetCount;
    double decisionCacheHitPercentage = 100 * (double)decisionCacheHitCount / (double)decisionCacheGetCount;
    EV_INFO << "Radio signal reception cache hit: " << receptionCacheHitPercentage << " %\n";
    EV_INFO << "Radio signal reception decision cache hit: " << decisionCacheHitPercentage << " %\n";
    recordScalar("Radio signal reception cache hit", receptionCacheHitPercentage, "%");
    recordScalar("Radio signal reception decision cache hit", decisionCacheHitPercentage, "%");
}

const IRadioSignalReception *CachedRadioChannel::getCachedReception(const IRadio *radio, const IRadioSignalTransmission *transmission) const
{
    int transmissionId = transmission->getId();
    int transmissionIndex = transmissionId - baseTransmissionId;
    if (transmissionIndex >= (int)cachedReceptions.size())
        return NULL;
    else
    {
        const std::vector<const IRadioSignalReception *> &cachedTransmissionReceptions = cachedReceptions[transmissionIndex];
        int radioId = radio->getId();
        return radioId >= (int)cachedTransmissionReceptions.size() ? NULL : cachedTransmissionReceptions[radioId];
    }
}

void CachedRadioChannel::setCachedReception(const IRadio *radio, const IRadioSignalTransmission *transmission, const IRadioSignalReception *reception)
{
    int transmissionId = transmission->getId();
    int transmissionIndex = transmissionId - baseTransmissionId;
    if (transmissionIndex >= (int)cachedReceptions.size())
        cachedReceptions.resize(transmissionIndex + 1);
    std::vector<const IRadioSignalReception *> &cachedTransmissionReceptions = cachedReceptions[transmissionIndex];
    int radioId = radio->getId();
    if (radioId >= (int)cachedTransmissionReceptions.size())
        cachedTransmissionReceptions.resize(radioId + 1);
    else
        delete cachedTransmissionReceptions[radioId];
    cachedTransmissionReceptions[radioId] = reception;
}

void CachedRadioChannel::removeCachedReception(const IRadio *radio, const IRadioSignalTransmission *transmission)
{
    std::vector<const IRadioSignalReception *> &cachedTransmissionReceptions = cachedReceptions[transmission->getId() - baseTransmissionId];
    int radioId = radio->getId();
    delete cachedTransmissionReceptions[radioId];
    cachedTransmissionReceptions[radioId] = NULL;
}

const IRadioSignalReceptionDecision *CachedRadioChannel::getCachedDecision(const IRadio *radio, const IRadioSignalTransmission *transmission) const
{
    int transmissionId = transmission->getId();
    int transmissionIndex = transmissionId - baseTransmissionId;
    if (transmissionIndex >= (int)cachedDecisions.size())
        return NULL;
    else
    {
        const std::vector<const IRadioSignalReceptionDecision *> &cachedTransmissionDecisions = cachedDecisions[transmissionIndex];
        int radioId = radio->getId();
        return radioId >= (int)cachedTransmissionDecisions.size() ? NULL : cachedTransmissionDecisions[radioId];
    }
}

void CachedRadioChannel::setCachedDecision(const IRadio *radio, const IRadioSignalTransmission *transmission, const IRadioSignalReceptionDecision *decision)
{
    int transmissionId = transmission->getId();
    int transmissionIndex = transmissionId - baseTransmissionId;
    if (transmissionIndex >= (int)cachedDecisions.size())
        cachedDecisions.resize(transmissionIndex + 1);
    std::vector<const IRadioSignalReceptionDecision *> &cachedTransmissionDecisions = cachedDecisions[transmissionIndex];
    int radioId = radio->getId();
    if (radioId >= (int)cachedTransmissionDecisions.size())
        cachedTransmissionDecisions.resize(radioId + 1);
    else
        delete cachedTransmissionDecisions[radioId];
    cachedTransmissionDecisions[radioId] = decision;
}

void CachedRadioChannel::removeCachedDecision(const IRadio *radio, const IRadioSignalTransmission *transmission)
{
    std::vector<const IRadioSignalReceptionDecision *> &cachedTransmissionDecisions = cachedDecisions[transmission->getId() - baseTransmissionId];
    int radioId = radio->getId();
    delete cachedTransmissionDecisions[radioId];
    cachedTransmissionDecisions[radioId] = NULL;
}

void CachedRadioChannel::invalidateCachedDecisions(const IRadioSignalTransmission *transmission)
{
    for (std::vector<std::vector<const IRadioSignalReceptionDecision *> >::iterator it = cachedDecisions.begin(); it != cachedDecisions.end(); it++)
    {
        std::vector<const IRadioSignalReceptionDecision *> &cachedTransmissionDecisions = *it;
        for (std::vector<const IRadioSignalReceptionDecision *>::iterator jt = cachedTransmissionDecisions.begin(); jt != cachedTransmissionDecisions.end(); jt++)
        {
            const IRadioSignalReceptionDecision *decision = *jt;
            if (decision)
            {
                const IRadioSignalReception *reception = decision->getReception();
                // TODO: instead of dropping the result we could update the noise only
                if (isInterferingTransmission(transmission, reception))
                    invalidateCachedDecision(decision);
            }
        }
    }
}

void CachedRadioChannel::invalidateCachedDecision(const IRadioSignalReceptionDecision *decision)
{
    const IRadioSignalReception *reception = decision->getReception();
    const IRadio *radio = reception->getReceiver();
    const IRadioSignalTransmission *transmission = reception->getTransmission();
    std::vector<const IRadioSignalReceptionDecision *> &cachedTransmissionDecisions = cachedDecisions[transmission->getId() - baseTransmissionId];
    int radioId = radio->getId();
    delete cachedTransmissionDecisions[radioId];
    cachedTransmissionDecisions[radioId] = NULL;
}

const IRadioSignalReception *CachedRadioChannel::getReception(const IRadio *radio, const IRadioSignalTransmission *transmission) const
{
    receptionCacheGetCount++;
    const IRadioSignalReception *reception = getCachedReception(radio, transmission);
    if (reception)
    {
        receptionCacheHitCount++;
        return reception;
    }
    else
        return RadioChannel::getReception(radio, transmission);
}

const IRadioSignalReceptionDecision *CachedRadioChannel::receiveFromChannel(const IRadio *radio, const IRadioSignalListening *listening, const IRadioSignalTransmission *transmission) const
{
    decisionCacheGetCount++;
    const IRadioSignalReceptionDecision *decision = getCachedDecision(radio, transmission);
    if (decision)
    {
        decisionCacheHitCount++;
        return decision;
    }
    else
        return RadioChannel::receiveFromChannel(radio, listening, transmission);
}
