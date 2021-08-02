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
#include <cstdlib>

using namespace phosphor::logging;

static std::vector<std::string> scpRWPath =  {
    "/sys/bus/i2c/devices/2-004f/1e78a0c0.i2c-bus:smpro@4f:misc/",
    "/sys/bus/i2c/devices/2-004e/1e78a0c0.i2c-bus:smpro@4e:misc/"
};

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

/** @brief implements command to read scp register
 *  @param - path, offset register to read
 *  @returns - 2 bytes value.
 */
uint16_t scpReadRegisterMap(std::string path, uint8_t offsetR)
{
    std::string cmd = "";
    std::string addrInStr;
    uint16_t addrInt;

    std::string nOffsetR = std::to_string(offsetR);
    cmd = "echo " + nOffsetR + " > " + path + "reg_addr";
    std::system(cmd.c_str());
    cmd = "cat " + path + "reg_rw";
    // Convert string to uint16_t
    addrInStr = exec(cmd.c_str());
    addrInt = strtol(addrInStr.c_str(), NULL, BASE);

    return addrInt;
}

/** @brief implements command to write scp register
 *  @param - path, offset and data to write
 *  @returns - None.
 */
static void scpWriteRegisterMap(std::string path, uint8_t offsetW, uint16_t dataW)
{
    std::string cmd = "";
    std::string nOffsetW = std::to_string(offsetW);
    std::string nDataW = std::to_string(dataW);
    cmd = "echo " + nOffsetW + " > " + path + "reg_addr";
    std::system(cmd.c_str());
    cmd = "echo " + nDataW + " > " + path + "reg_rw";
    std::system(cmd.c_str());
}

/** @brief implements ipmi oem command read scp register
 *  @param - cpuIndex, offsetRead
 *  @returns - value hex format.
 */
auto ipmiDocmdScpReadRegisterMap(uint8_t cpuIndex, uint8_t offsetR)
    -> ipmi::RspType<uint8_t, uint8_t>
{
    try
    {
        uint8_t firstByte;
        uint8_t secondByte;
        uint16_t addr;

        if (cpuIndex == 0) {
            addr = scpReadRegisterMap(scpRWPath[0], offsetR);
        } else if (cpuIndex == 1) {
            addr = scpReadRegisterMap(scpRWPath[1], offsetR);
        } else {
            return responseFailure();
        }
        firstByte = (uint8_t)(addr & 0xff);
        secondByte = (uint8_t)(addr >> 8);

        return ipmi::responseSuccess(firstByte, secondByte);
    }
    catch(const std::exception& e) {
        return responseFailure();
    }
}

/** @brief implements ipmi oem command write scp register
 *  @param - cpuIndex, offsetRead and data write byte 0/1
 *  @returns - Fail or Success.
 */
ipmi::RspType<> ipmiDocmdScpWriteRegisterMap(uint8_t cpuIndex, uint8_t offsetW, uint8_t firstData, uint8_t secondData)
{
    try
    {
        uint16_t dataW =  ((uint16_t)secondData << 8) | (uint16_t)firstData;
        if (cpuIndex == 0) {
            scpWriteRegisterMap(scpRWPath[0], offsetW, dataW);
        } else if (cpuIndex == 1) {
            scpWriteRegisterMap(scpRWPath[1], offsetW, dataW);
        } else {
            return responseFailure();
        }
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
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::ampere::netFnAmpere,
                          ipmi::general::cmdScpRead, ipmi::Privilege::User,
                          ipmiDocmdScpReadRegisterMap);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::ampere::netFnAmpere,
                          ipmi::general::cmdScpWrite, ipmi::Privilege::User,
                          ipmiDocmdScpWriteRegisterMap);

}
