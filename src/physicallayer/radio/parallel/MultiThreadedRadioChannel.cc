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

#include <MultiThreadedRadioChannel.h>

Define_Module(MultiThreadedRadioChannel);

MultiThreadedRadioChannel::~MultiThreadedRadioChannel()
{
    terminateWorkers();
}

void MultiThreadedRadioChannel::initialize(int stage)
{
    RadioChannel::initialize(stage);
    if (stage == INITSTAGE_LOCAL)
    {
        initializeWorkers(3);
    }
}

void MultiThreadedRadioChannel::initializeWorkers(int workerCount)
{
    isWorkersEnabled = true;
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&jobsLock, NULL);
    pthread_mutex_init(&cacheLock, &mutexattr);
    pthread_condattr_t condattr;
    pthread_condattr_init(&condattr);
    pthread_cond_init(&jobsCondition, &condattr);
    pthread_condattr_destroy(&condattr);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    for (int i = 0; i < workerCount; i++)
    {
        pthread_t *worker = new pthread_t();
        pthread_create(worker, &attr, callWorkerMain, this);
        // TODO: non portable
//        cpu_set_t cpuset;
//        CPU_ZERO(&cpuset);
//        for (int j = 0; j < 6; j++)
//            CPU_SET(j, &cpuset);
//        pthread_setaffinity_np(*worker, sizeof(cpu_set_t), &cpuset);
        workers.push_back(worker);
    }
    pthread_attr_destroy(&attr);
}

void MultiThreadedRadioChannel::terminateWorkers()
{
    isWorkersEnabled = false;
    pthread_mutex_lock(&jobsLock);
    invalidateCacheJobs.clear();
    while (!computeCacheJobs.empty())
        computeCacheJobs.pop();
    pthread_cond_broadcast(&jobsCondition);
    pthread_mutex_unlock(&jobsLock);
    for (std::vector<pthread_t *>::iterator it = workers.begin(); it != workers.end(); it++)
    {
        void *status;
        pthread_t *worker = *it;
        pthread_join(*worker, &status);
        delete worker;
    }
    pthread_cond_destroy(&jobsCondition);
    pthread_mutex_destroy(&jobsLock);
    pthread_mutex_destroy(&cacheLock);
}

void *MultiThreadedRadioChannel::callWorkerMain(void *argument)
{
    return ((MultiThreadedRadioChannel *)argument)->workerMain(argument);
}

void *MultiThreadedRadioChannel::workerMain(void *argument)
{
    while (isWorkersEnabled)
    {
        pthread_mutex_lock(&jobsLock);
        while (isWorkersEnabled && invalidateCacheJobs.empty() && computeCacheJobs.empty())
            pthread_cond_wait(&jobsCondition, &jobsLock);
        EV_DEBUG << "Worker " << pthread_self() << " is looking for jobs on CPU " << sched_getcpu() << endl;
        if (!invalidateCacheJobs.empty())
        {
            const InvalidateCacheJob invalidateCacheJob = invalidateCacheJobs.front();
            invalidateCacheJobs.pop_front();
            EV_DEBUG << "Worker " << pthread_self() << " is running invalidate cache " << &invalidateCacheJob << endl;
            pthread_mutex_unlock(&jobsLock);
            // TODO: this is a race condition with the main thread when receiving a signal
            invalidateCachedDecisions(invalidateCacheJob.transmission);
            pthread_mutex_lock(&jobsLock);
            pthread_cond_broadcast(&jobsCondition);
            pthread_mutex_unlock(&jobsLock);
        }
        else if (!computeCacheJobs.empty())
        {
            const ComputeCacheJob computeCacheJob = computeCacheJobs.top();
            computeCacheJobs.pop();
            EV_DEBUG << "Worker " << pthread_self() << " is computing reception at " << computeCacheJob.receptionStartTime << endl;
            std::vector<const IRadioSignalTransmission *> *transmissionsCopy = new std::vector<const IRadioSignalTransmission *>(transmissions);
            pthread_mutex_unlock(&jobsLock);
            const IRadioSignalReceptionDecision *decision = computeReceptionDecision(computeCacheJob.radio, computeCacheJob.listening, computeCacheJob.transmission, transmissionsCopy);
            setCachedDecision(computeCacheJob.radio, computeCacheJob.transmission, decision);
            delete computeCacheJob.listening;
            delete transmissionsCopy;
        }
        else
            pthread_mutex_unlock(&jobsLock);
    }
    return NULL;
}

const IRadioSignalArrival *MultiThreadedRadioChannel::getCachedArrival(const IRadio *radio, const IRadioSignalTransmission *transmission) const
{
    const IRadioSignalArrival *arrival = NULL;
    pthread_mutex_lock(&cacheLock);
    arrival = RadioChannel::getCachedArrival(radio, transmission);
    pthread_mutex_unlock(&cacheLock);
    return arrival;
}

void MultiThreadedRadioChannel::setCachedArrival(const IRadio *radio, const IRadioSignalTransmission *transmission, const IRadioSignalArrival *arrival) const
{
    pthread_mutex_lock(&cacheLock);
    RadioChannel::setCachedArrival(radio, transmission, arrival);
    pthread_mutex_unlock(&cacheLock);
}

void MultiThreadedRadioChannel::removeCachedArrival(const IRadio *radio, const IRadioSignalTransmission *transmission) const
{
    pthread_mutex_lock(&cacheLock);
    RadioChannel::removeCachedArrival(radio, transmission);
    pthread_mutex_unlock(&cacheLock);
}

const IRadioSignalReception *MultiThreadedRadioChannel::getCachedReception(const IRadio *radio, const IRadioSignalTransmission *transmission) const
{
    const IRadioSignalReception *reception = NULL;
    pthread_mutex_lock(&cacheLock);
    reception = RadioChannel::getCachedReception(radio, transmission);
    pthread_mutex_unlock(&cacheLock);
    return reception;
}

void MultiThreadedRadioChannel::setCachedReception(const IRadio *radio, const IRadioSignalTransmission *transmission, const IRadioSignalReception *reception) const
{
    pthread_mutex_lock(&cacheLock);
    RadioChannel::setCachedReception(radio, transmission, reception);
    pthread_mutex_unlock(&cacheLock);
}

void MultiThreadedRadioChannel::removeCachedReception(const IRadio *radio, const IRadioSignalTransmission *transmission) const
{
    pthread_mutex_lock(&cacheLock);
    RadioChannel::removeCachedReception(radio, transmission);
    pthread_mutex_unlock(&cacheLock);
}

const IRadioSignalReceptionDecision *MultiThreadedRadioChannel::getCachedDecision(const IRadio *radio, const IRadioSignalTransmission *transmission) const
{
    const IRadioSignalReceptionDecision *decision = NULL;
    pthread_mutex_lock(&cacheLock);
    decision = RadioChannel::getCachedDecision(radio, transmission);
    pthread_mutex_unlock(&cacheLock);
    return decision;
}

void MultiThreadedRadioChannel::setCachedDecision(const IRadio *radio, const IRadioSignalTransmission *transmission, const IRadioSignalReceptionDecision *decision)
{
    pthread_mutex_lock(&cacheLock);
    RadioChannel::setCachedDecision(radio, transmission, decision);
    pthread_mutex_unlock(&cacheLock);
}

void MultiThreadedRadioChannel::removeCachedDecision(const IRadio *radio, const IRadioSignalTransmission *transmission)
{
    pthread_mutex_lock(&cacheLock);
    RadioChannel::removeCachedDecision(radio, transmission);
    pthread_mutex_unlock(&cacheLock);
}

void MultiThreadedRadioChannel::invalidateCachedDecisions(const IRadioSignalTransmission *transmission)
{
    pthread_mutex_lock(&cacheLock);
    RadioChannel::invalidateCachedDecisions(transmission);
    pthread_mutex_unlock(&cacheLock);
}

void MultiThreadedRadioChannel::invalidateCachedDecision(const IRadioSignalReceptionDecision *decision)
{
    const IRadioSignalReception *reception = decision->getReception();
    pthread_mutex_lock(&cacheLock);
    RadioChannel::invalidateCachedDecision(decision);
    pthread_mutex_unlock(&cacheLock);
    const IRadio *radio = reception->getReceiver();
    const IRadioSignalTransmission *transmission = reception->getTransmission();
    const IRadioSignalListening *listening = radio->getReceiver()->createListening(radio, transmission->getStartTime(), transmission->getEndTime(), transmission->getStartPosition(), transmission->getEndPosition());
    simtime_t startTime = reception->getStartTime();
    pthread_mutex_lock(&jobsLock);
    computeCacheJobs.push(ComputeCacheJob(radio, listening, transmission, startTime));
    pthread_mutex_unlock(&jobsLock);
}

void MultiThreadedRadioChannel::transmitToChannel(const IRadio *transmitterRadio, const IRadioSignalTransmission *transmission)
{
    EV_DEBUG << "Radio " << transmitterRadio << " transmits signal " << transmission << endl;
    pthread_mutex_lock(&cacheLock);
    RadioChannel::transmitToChannel(transmitterRadio, transmission);
    pthread_mutex_unlock(&cacheLock);
    pthread_mutex_lock(&jobsLock);
    invalidateCacheJobs.push_back(InvalidateCacheJob(transmission));
    for (std::vector<const IRadio *>::iterator it = radios.begin(); it != radios.end(); it++) {
        const IRadio *receiverRadio = *it;
        // TODO: merge with sendRadioFrame!
        if (transmitterRadio != receiverRadio && isPotentialReceiver(receiverRadio, transmission)) {
            const simtime_t receptionStartTime = getArrival(receiverRadio, transmission)->getStartTime();
            const IRadioSignalListening *listening = receiverRadio->getReceiver()->createListening(receiverRadio, transmission->getStartTime(), transmission->getEndTime(), transmission->getStartPosition(), transmission->getEndPosition());
            computeCacheJobs.push(ComputeCacheJob(receiverRadio, listening, transmission, receptionStartTime));
        }
    }
    // TODO: what shall we do with already running computation jobs?
    EV_DEBUG << "Transmission count: " << transmissions.size() << " job count: " << computeCacheJobs.size() << " decision cache hit count: " << cacheDecisionHitCount << " decision cache get count: " << cacheDecisionGetCount << " decision cache %: " << (100 * (double)cacheDecisionHitCount / (double)cacheDecisionGetCount) << "%\n";
    pthread_cond_broadcast(&jobsCondition);
    pthread_mutex_unlock(&jobsLock);
}

const IRadioSignalReceptionDecision *MultiThreadedRadioChannel::receiveFromChannel(const IRadio *radio, const IRadioSignalListening *listening, const IRadioSignalTransmission *transmission) const
{
    EV_DEBUG << "Radio " << radio << " receives signal " << transmission << endl;
    pthread_mutex_lock(&jobsLock);
    while (!invalidateCacheJobs.empty())
        pthread_cond_wait(&jobsCondition, &jobsLock);
    pthread_mutex_unlock(&jobsLock);
    return RadioChannel::receiveFromChannel(radio, listening, transmission);
}
