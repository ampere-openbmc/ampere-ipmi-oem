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

/** @brief execute a command and get the output of the command
 *  @param[in] the command
 *  @returns output of the command
 */
std::string exec(const char* cmd) {
    char buffer[128];
    std::string result = "";
    /* Pipe stream from a command */
    FILE* pipe = popen(cmd, "r");
    if (!pipe) throw std::runtime_error("popen() failed!");
    try {
        /* Reads a line from the specified stream and stores it */
        while (fgets(buffer, sizeof buffer, pipe) != NULL) {
            result += buffer;
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    /* Close a stream that was opened by popen() */
    pclose(pipe);
    return result;
}

/** @brief implements sync RTC time to BMC commands
 *  @param - None
 *  @returns IPMI completion code.
 */
ipmi::RspType<> ipmiSyncRTCTimeToBMC()
{
    std::string cmd;
    std::string cmdOutput;
    try
    {
        /* Check the mode of NTP in the system, set the system time in case the
         * NTP mode is disabled.
         */
        cmd = "systemctl status systemd-timesyncd.service | grep inactive";
        cmdOutput = exec(cmd.c_str());
        if (cmdOutput.empty())
        {
            log<level::INFO>("Can not set system time while the mode is NTP");
            return responseFailure();
        }
        else
        {
            /* Sync time from RTC to BMC using hwclock */
            system("hwclock --hctosys");
        }
    }
    catch(const std::exception& e)
    {
        log<level::ERR>(e.what());
        return responseFailure();
    }

    return ipmi::responseSuccess();
}

ipmi::RspType<> ipmiDocmdConfigureUartSwitch(uint8_t consPort, uint8_t dirSw)
{
    try
    {
        std::string cmd = "";
        /* Convert uint8 to string */
        consPort = consPort + 1;
        std::string nConsPort = std::to_string(consPort);
        std::string nDirSw = std::to_string(dirSw);

        /*
        Do command /usr/sbin/ampere_uartmux_ctrl.sh <Console Port> <Direction>
        Example of CPU console: ipmitool raw 0x3c 0xb0 0x00 0x01
        */
        cmd = "/usr/sbin/ampere_uartmux_ctrl.sh " + nConsPort + " " + nDirSw;
        std::system(cmd.c_str());
    }
    catch(const std::exception& e)
    {
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
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::ampere::netFnAmpere,
                          ipmi::general::cmdUartSW, ipmi::Privilege::User,
                          ipmiDocmdConfigureUartSwitch);
}
