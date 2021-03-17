/*
 * Copyright (c) 2018-2021 Ampere Computing LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <bridgingcommands.hpp>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/message.hpp>
#include <storagecommands.hpp>
#include <user_channel/channel_layer.hpp>

#include <bitset>
#include <cstring>
#include <vector>

static Bridging bridging;
static bool eventMessageBufferFlag = false;

void Bridging::clearResponseQueue()
{
    responseQueue.clear();
}

void Bridging::insertMessageInQueue(IpmbResponse msg)
{
    responseQueue.insert(responseQueue.end(), std::move(msg));
}

void Bridging::eraseMessageFromQueue()
{
    responseQueue.erase(responseQueue.begin());
}

IpmbResponse Bridging::getMessageFromQueue()
{
    return responseQueue.front();
}

std::size_t Bridging::getResponseQueueSize()
{
    return responseQueue.size();
}

/** @brief This command is used to flush unread data from the receive
 *   message queue
 *  @param receiveMessage  - clear receive message queue
 *  @param eventMsgBufFull - clear event message buffer full
 *  @param reserved2       - reserved bit
 *  @param watchdogTimeout - clear watchdog pre-timeout interrupt flag
 *  @param reserved1       - reserved bit
 *  @param oem0            - clear OEM 0 data
 *  @param oem1            - clear OEM 1 data
 *  @param oem2            - clear OEM 2 data

 *  @return IPMI completion code on success
 */
ipmi::RspType<> ipmiAppClearMessageFlags(ipmi::Context::ptr ctx,
                                         bool receiveMessage,
                                         bool eventMsgBufFull, bool reserved2,
                                         bool watchdogTimeout, bool reserved1,
                                         bool oem0, bool oem1, bool oem2)
{
    ipmi::ChannelInfo chInfo;

    try
    {
        getChannelInfo(ctx->channel, chInfo);
    }
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiAppClearMessageFlags: Failed to get Channel Info",
            phosphor::logging::entry("MSG: %s", e.description()));
        return ipmi::responseUnspecifiedError();
    }
    if (chInfo.mediumType !=
        static_cast<uint8_t>(ipmi::EChannelMediumType::smbusV20))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiAppClearMessageFlags: Error - supported only in SSIF "
            "interface");
        return ipmi::responseCommandNotAvailable();
    }

    if (reserved1 || reserved2)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    if (receiveMessage)
    {
        bridging.clearResponseQueue();
    }

    if (eventMessageBufferFlag != true && eventMsgBufFull == true)
    {
        eventMessageBufferFlag = true;
    }

    // As phosphor-watchdog has not supported PreTimeoutInterruptFlags yet,
    // so do nothing on clear watchdog pre-timeout interrupt flags.

    return ipmi::responseSuccess();
}

void registerBridingFunctions() __attribute__((constructor));
void registerBridingFunctions()
{
    // <Clear Message Flags Command>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnApp,
                          ipmi::app::cmdClearMessageFlags,
                          ipmi::Privilege::User, ipmiAppClearMessageFlags);

    return;
}
