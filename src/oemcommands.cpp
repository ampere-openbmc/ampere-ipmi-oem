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

#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>
#include "oemcommands.hpp"

using namespace phosphor::logging;

static inline auto response(uint8_t cc)
{
    return std::make_tuple(cc, std::nullopt);
}

static inline auto responseFailure()
{
    return response(responseFail);
}

ipmi::RspType<> ipmiSyncRTCTimeToBMC()
{
    try
    {
        /* Sync time from RTC to BMC using hwclock */
        system("hwclock --hctosys");
    }
    catch(const std::exception& e)
    {
        log<level::ERR>(e.what());
        return responseFailure();
    }

    return ipmi::responseSuccess();
}

void registerOEMFunctions() __attribute__((constructor));
void registerOEMFunctions()
{
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::ampere::netFnAmpere,
                          ipmi::general::cmdSyncRtcTime,
                          ipmi::Privilege::User, ipmiSyncRTCTimeToBMC);
}
