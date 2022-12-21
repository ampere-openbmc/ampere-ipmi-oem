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
#include <boost/container/flat_map.hpp>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <dirent.h>
#include <fstream>
#include <iostream>

using namespace phosphor::logging;

using BasicVariantType =
    std::variant<std::vector<std::string>, std::string, int64_t, uint64_t,
                 double, int32_t, uint32_t, int16_t, uint16_t, uint8_t, bool>;
using FruObjectType = boost::container::flat_map<
    sdbusplus::message::object_path,
    boost::container::flat_map<
        std::string,
        boost::container::flat_map<std::string, BasicVariantType>>>;

static std::vector<std::string> scpRWPath =  {
    "/sys/bus/platform/devices/smpro-misc.2.auto/reg",
    "/sys/bus/platform/devices/smpro-misc.5.auto/reg",
};

constexpr static const char* fruDeviceServiceName =
    "xyz.openbmc_project.FruDevice";

constexpr static const char* chassisTypeRackMount = "23";

static inline auto response(uint8_t cc)
{
    return std::make_tuple(cc, std::nullopt);
}

static inline auto responseFailure()
{
    return response(responseFail);
}

static inline auto responseInvalidFanNumber()
{
    return response(responseInvalidFanNum);
}

static inline auto responseSetFanErrorThermalCtlNotDisabled()
{
    return response(responseSetFanError);
}

/** @brief get Baseboard FRU's address
 *  @param - busIdx, address of I2C device
 *  @returns - true if successfully, false if fail
 */
[[maybe_unused]] static bool getBaseBoardFRUAddr(uint8_t &busIdx, uint8_t &addr)
{
    bool retVal = false;
    sd_bus* bus = NULL;
    FruObjectType fruObjects;

    /*
     * Read all managed objects of FRU device
     */
    int ret = sd_bus_default_system(&bus);
    if (ret < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to connect to system bus");
        sd_bus_unref(bus);
        return false;
    }
    sdbusplus::bus::bus dbus(bus);
    auto mapperCall =
        dbus.new_method_call(fruDeviceServiceName,
                             "/",
                             "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");

    try
    {
        auto mapperReply = dbus.call(mapperCall);
        mapperReply.read(fruObjects);
    }
    catch (sdbusplus::exception_t& e)
    {
        log<level::ERR>("Fail to call GetManagedObjects method");

        sd_bus_unref(bus);
        return false;
    }

    /*
     * Scan all FRU objects to find out baseboard FRU device.
     * The basedboard FRU device is indecate by chassis type
     * is Rack Mount - "23"
     */
    for(const auto &fruObj : fruObjects)
    {
        auto fruDeviceInf = fruObj.second.find("xyz.openbmc_project.FruDevice");

        if(fruDeviceInf != fruObj.second.end())
        {
            auto chassisProperty = fruDeviceInf->second.find("CHASSIS_TYPE");

            if(chassisProperty != fruDeviceInf->second.end())
            {
                std::string chassisType = std::get<std::string>(chassisProperty->second);
                auto busProperty = fruDeviceInf->second.find("BUS");
                auto addrProperty = fruDeviceInf->second.find("ADDRESS");

                if((0 == chassisType.compare(chassisTypeRackMount)) && 
                    (busProperty != fruDeviceInf->second.end()) &&
                    (addrProperty != fruDeviceInf->second.end()))
                {
                    busIdx = (uint8_t)std::get<uint32_t>(busProperty->second);
                    addr = (uint8_t)std::get<uint32_t>(addrProperty->second);
                    retVal = true;
                    break;
                }
            }
        }
    }

    sd_bus_unref(bus);
    return retVal;
}

/** @brief get Raw FRU's data
 *  @param - busIdx, address of I2C device.
 *         - fruData: data have been read
 *  @returns - true if successfully, false if fail
 */
static bool getRawFruData(uint8_t busIdx, uint8_t addr, std::vector<uint8_t> &fruData)
{
    bool retVal = false;
    sd_bus* bus = NULL;
    int ret = sd_bus_default_system(&bus);

    if (ret < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to connect to system bus",
            phosphor::logging::entry("ERRNO=0x%X", -ret));
    }
    else
    {
        sdbusplus::bus::bus dbus(bus);
        auto MapperCall =
            dbus.new_method_call(fruDeviceServiceName,
                                "/xyz/openbmc_project/FruDevice",
                                "xyz.openbmc_project.FruDeviceManager", "GetRawFru");

        MapperCall.append(busIdx, addr);

        try
        {
            auto mapperReply = dbus.call(MapperCall);
            mapperReply.read(fruData);
            retVal = true;
        }
        catch (sdbusplus::exception_t& e)
        {
            log<level::ERR>("Fail to read Raw FRU data from system bus\n");
        }
    }

    sd_bus_unref(bus);

    return retVal;
}

/** @brief update MAC address information in FRU data
 *  @param - fruData: FRU data
 *         - macAddress: MAC address information
 *  @returns - true if successfully, false if fail
 */
static bool updateMACAddInFRU(std::vector<uint8_t> &fruData, std::vector<uint8_t> macAddress)
{
    bool retVal = false;
    uint32_t areaOffset = fruData[3] * 8; /* Board area start offset */
    char macAddressStr[18];
    uint32_t boardLeng = 0;
    uint8_t  checkSumVal = 0;

    /*
     * Update MAC address at first custom field of Board Information Area.
     */
    if(areaOffset != 0)
    {
        /*
         * The Board Manufacturer type/length byte is stored
         * at byte 0x06 of Board area.
         */
        uint32_t fieldOffset = areaOffset + 6;

        /*
         * Scan all 5 predefined fields of Board area to jump to
         * first Custom field.
         */
        for(uint32_t i = 0; i < 5; i++)
        {
            fieldOffset += (fruData[fieldOffset] & 0x3f) + 1;
        }

        /*
         * Update the MAC address information when type/length is not
         * EndOfField byte and the length of Custom field is 17.
         */
        if((fruData[fieldOffset] != 0xc1) && ((uint8_t)17 == (fruData[fieldOffset] & (uint8_t)0x3f)))
        {
            sprintf(macAddressStr, "%02X:%02X:%02X:%02X:%02X:%02X", macAddress[0], macAddress[1], macAddress[2], macAddress[3], macAddress[4], macAddress[5]);

            /*
             * Update 17 bytes of MAC address information
             */
            fieldOffset++;
            for(uint32_t i = 0; i < 17; i++)
            {
                fruData[fieldOffset + i] = macAddressStr[i];
            }

            /*
             * Re-caculate the checksum of Board Information Area.
             */
            boardLeng = fruData[areaOffset + 1] * 8;
            for(uint32_t i = 0; i < boardLeng -1; i++)
            {
                checkSumVal += fruData[areaOffset + i];
            }

            checkSumVal = ~checkSumVal + 1;
            fruData[areaOffset + boardLeng - 1] = checkSumVal;

            retVal = true;
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
            "FRU does not include MAC address information");
        }
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
        "FRU does not include Board Information Area");
    }

    return retVal;
}

/** @brief write FRU data to EEPROM
 *  @param - busIdx and address of I2C device.
 *         - fruData: FRU data
 *  @returns - true if successfully, false if fail
 */
static bool writeFruData(uint8_t busIdx, uint8_t addr, std::vector<uint8_t> &fruData)
{
    bool retVal = false;
    sd_bus* bus = NULL;
    int ret = sd_bus_default_system(&bus);

    if (ret < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to connect to system bus",
            phosphor::logging::entry("ERRNO=0x%X", -ret));
    }
    else
    {
        sdbusplus::bus::bus dbus(bus);
        auto MapperCall =
            dbus.new_method_call(fruDeviceServiceName,
                                "/xyz/openbmc_project/FruDevice",
                                "xyz.openbmc_project.FruDeviceManager", "WriteFru");

        MapperCall.append(busIdx, addr, fruData);

        try
        {
            auto mapperReply = dbus.call(MapperCall);
            retVal = true;
        }
        catch (sdbusplus::exception_t& e)
        {
            log<level::ERR>("Fail to Write FRU data via system bus\n");
        }
    }

    sd_bus_unref(bus);

    return retVal;
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
    int ret;
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
            ret = system("hwclock --hctosys");
            if (ret == -1)
            {
                log<level::ERR>("Can not set system time");
            }
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
    int ret;
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
        ret = std::system(cmd.c_str());
        if (ret == -1)
        {
            log<level::ERR>("Can not config UART switch");
        }
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
std::optional<std::uint16_t> scpReadRegisterMap(std::string path, uint8_t offsetR)
{
    uint16_t addrInt;
    std::fstream file;

    try
    {
        file.open(path, std::ios::in);
        if (!file.is_open()){
            return std::nullopt;
        }
        file.seekg(offsetR, std::ios::beg);
        file.read((char*)(&addrInt), 2);
        file.close();
    } catch (const std::exception& e) {
        log<level::ERR>("Can not read register map");
        return std::nullopt;
    }

    return addrInt;
}

/** @brief implements command to write scp register
 *  @param - path, offset and data to write
 *  @returns - None.
 */
static bool scpWriteRegisterMap(std::string path, uint8_t offsetW, uint16_t dataW)
{
    std::fstream file;

    try
    {
        file.open(path, std::ios::out);
        if (!file.is_open()){
            return false;
        }
        file.seekg(offsetW, std::ios::beg);
        file.write((char*)(&dataW), 2);
        file.close();

    } catch (const std::exception& e) {
        log<level::ERR>("Can not write register map");
        return false;
    }

    return true;
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
        std::optional<std::uint16_t> addr;

        if ( cpuIndex != 0 && cpuIndex != 1 ){
            return responseFailure();
        }
        addr = scpReadRegisterMap(scpRWPath[cpuIndex], offsetR);
        if(addr == std::nullopt){
            return responseFailure();
        }

        firstByte = (uint8_t)(addr.value() >> 8);
        secondByte = (uint8_t)(addr.value() & 0xff);

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
        uint16_t dataW =  ((uint16_t)firstData << 8) | (uint16_t)secondData;
        if (cpuIndex != 0 && cpuIndex != 1 ) {
            return responseFailure();
        }
        if(!scpWriteRegisterMap(scpRWPath[cpuIndex], offsetW, dataW))
        {
            return responseFailure();
        }
    }
    catch(const std::exception& e)
    {
        return responseFailure();
    }

    return ipmi::responseSuccess();
}

/** @brief implements ipmi oem command edit MAC address
 *  @param - new macAddress
 *  @returns - Fail or Success.
 */
ipmi::RspType<uint8_t> ipmiDocmdSetMacAddress(std::vector<uint8_t> macAddress)
{
    std::vector<uint8_t> fruData;
    uint8_t busIdx = 0;
    uint8_t addrss = 0;

    if(macAddress.size() != 6)
    {
        log<level::ERR>("new MAC address is invalid");
        return responseFailure();
    }

#if defined(MAC_ADDRESS_FRU_BUS) && defined(MAC_ADDRESS_FRU_ADDR)
    /* Set BUS and Address of FRU device that includes MAC address */
    busIdx = MAC_ADDRESS_FRU_BUS;
    addrss = MAC_ADDRESS_FRU_ADDR;
#else
    /* Calculate BUS and Address of FRU device that includes MAC address */
    if(!getBaseBoardFRUAddr(busIdx, addrss))
    {
        log<level::ERR>("Can not get the bus and address of baseboard FRU device");
        return responseFailure();
    }
#endif

    if(!getRawFruData(busIdx, addrss, fruData))
    {
        log<level::ERR>("Can not get raw FRU data");
        return responseFailure();
    }

    if(!updateMACAddInFRU(fruData, macAddress))
    {
        log<level::ERR>("Can not update MAC address");
        return responseFailure();
    }

    if(!writeFruData(busIdx, addrss, fruData))
    {
        log<level::ERR>("Can not Write FRU data");
        return responseFailure();
    }

    return ipmi::responseSuccess(macAddress.size());
}

/** @brief implements check ampere_fanctrl.sh script is exist
 *  @param - None
 *  @returns IPMI completion code: 0x00: exist, 0x01: Not exist.
 */
static bool checkFanCtrlScriptExist()
{
    /* Check ampere_fanctrl.sh script is exist */
    if (!access(fanCtrlScript.c_str(), F_OK))
        return 0;
    else
        return 1;
}

/** @brief implements get fan status function
 *  @param - None
 *  @returns IPMI completion code: 0x00: enabled, 0x01: disabled
 */
static bool getFanStatus()
{
    std::string cmd;
    int fanStt;

    /* Check status of the fan service */
    cmd = "ampere_fanctrl.sh getstatus";
    fanStt = system(cmd.c_str());
    if (WEXITSTATUS(fanStt) == 0)
        return 0;
    else
        return 1;
}

/** @brief implements get fan status command
 *  @param - None
 *  @returns IPMI completion code: 0x00: enabled, 0x01: disabled
 */
ipmi::RspType<uint8_t> ipmiGetFanControlStatus()
{
    try
    {
        /* Check ampere_fanctrl.sh script is exist */
        if (checkFanCtrlScriptExist() == fileNotExists)
        {
            log<level::ERR>("Error: ampere_fanctrl.sh script is not exist");
            return ipmi::responseUnspecifiedError();
        }
        /* Check status of the fan service */
        if (getFanStatus() == responseEnabled)
        {
            /* The status of the fan service is active */
            log<level::INFO>("Fan speed control is enabled");
            return ipmi::responseSuccess(responseEnabled);
        }
        else
        {
            /* The status of the fan service is inactive */
            log<level::INFO>("Fan speed control is disabled");
            return ipmi::responseSuccess(responseDisabled);
        }
    }
    catch(const std::exception& e)
    {
        log<level::ERR>(e.what());
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess();
}

/** @brief implements set fan status command
 *  @param - status 0x00: enabled, 0x01: disabled
 *  @returns IPMI completion code: 0x00: enabled, 0x01: disabled
 */
ipmi::RspType<uint8_t> ipmiSetFanControlStatus(uint8_t status)
{
    std::string cmd;
    int ret;
    try
    {
        /* Check ampere_fanctrl.sh script is exist */
        if (checkFanCtrlScriptExist() == fileNotExists)
        {
            log<level::ERR>("Error: ampere_fanctrl.sh script is not exist");
            return ipmi::responseUnspecifiedError();
        }

        /* Enable/Disable the fan speed control */
        log<level::INFO>("Enable/Disable Fan speed control service");
        cmd = "ampere_fanctrl.sh setstatus " + std::to_string(status);
        ret = std::system(cmd.c_str());
        if (ret == -1)
        {
            log<level::ERR>("Error: can not set fan control status");
        }
        return ipmi::responseSuccess(status);
    }
    catch(const std::exception& e)
    {
        log<level::ERR>(e.what());
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess();
}

/** @brief implements set fan status command
 *  @param - status 0x00: enabled, 0x01: disabled
 *  @returns IPMI completion code: 0x00: enabled, 0x01: disabled
 */
ipmi::RspType<uint8_t> ipmiSetFanSpeed(uint8_t fanNumber, uint8_t speed)
{
    std::string cmd = "";
    std::string fanNumberStr;
    std::string speedStr;
    int setFanStt;

    try
    {
        /* Check the PWM duty cycle is valid */
        if ((speed < 1) || (speed > 100))
        {
            log<level::ERR>("Error: Invalid PWM duty cycle");
            return ipmi::responseUnspecifiedError();
        }

        /* Check the Fan speed control status */
        if (getFanStatus() == responseEnabled)
        {
            log<level::ERR>("Error: can not set Fan speed because thermal "
                            "control is not disabled");
            return responseSetFanErrorThermalCtlNotDisabled();
        }

        /* Check ampere_fanctrl.sh script is exist */
        if (checkFanCtrlScriptExist() == fileNotExists)
        {
            log<level::ERR>("Error: ampere_fanctrl.sh script is not exist");
            return ipmi::responseUnspecifiedError();
        }

        fanNumberStr = std::to_string(fanNumber);
        speedStr = std::to_string(speed);
        /* Call ampere_fanctrl.sh script for setting fan speed */
        cmd = "ampere_fanctrl.sh setspeed " + fanNumberStr + " " + speedStr;
        setFanStt = system(cmd.c_str());
        if (WEXITSTATUS(setFanStt) == 1)
        {
            log<level::ERR>("Error: Invalid fan number");
            return responseInvalidFanNumber();
        }
    }
    catch(const std::exception& e)
    {
        log<level::ERR>(e.what());
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(responseEnabled);
}

/** @brief implements set firmware in-band update status
 *  @param - ctx - shared_ptr to an IPMI context struct
 *  @param - updateStatus 0x00: Update Started
 *                        0x01: Update Completed with success
 *                        0x02: Update Completed with failure
 *         - updateType   0x00: Update entire Host FW
 *                        0x01: Update RO regions of Host FW
 *                              (preserve RW regions)
 *                        0x02: Update RO regions of Host FW
 *                              (clear RW regions)
 *  @returns IPMI completion code: 0x00: success, 0xD6: Handle command failure
 */
ipmi::RspType<>
    ipmiSetFWInbandUpdateStatus(ipmi::Context::ptr ctx,
                                uint8_t updateStatus,
                                uint8_t updateType)
{
    ipmi::ChannelInfo chInfo;

    try {
        getChannelInfo(ctx->channel, chInfo);
    }
    catch (sdbusplus::exception_t& e) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiSetFWInbandUpdateStatus: Failed to get Channel Info",
            phosphor::logging::entry("MSG: %s", e.description()));
        return ipmi::responseUnspecifiedError();
    }
    if (chInfo.mediumType !=
        static_cast<uint8_t>(ipmi::EChannelMediumType::smbusV20)) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiSetFWInbandUpdateStatus: Error - supported only in SSIF "
            "interface");
        return ipmi::responseCommandNotAvailable();
    }

    try
    {
        /* Check update status */
        if (updateStatus != FWUpdateStarted &&
            updateStatus != FWUpdateSuccess &&
            updateStatus != FWUpdateFailure)
        {
            log<level::ERR>("Error: Invalid FW inband update status");
            return ipmi::responseCommandDisabled();
        }

        /* Check update type */
        if (updateType != FWUpdateEntireHostFW &&
            updateType != FWUpdatePreserveRW &&
            updateType != FWUpdateClearRW)
        {
            log<level::ERR>("Error: Invalid FW inband update type");
            return ipmi::responseCommandDisabled();
        }

        /* Create the SEL log */
        if (updateStatus == FWUpdateStarted || updateStatus == FWUpdateSuccess)
        {
            /* Create an Ampere OK SEL event */
            std::string messageStr = "Firmware In-band Update Status: " +
                FWUpdateStatusStr[updateStatus] + " with " +
                FWUpdateTypeStr[updateType];
            std::string redfishMsgId("OpenBMC.0.1.AmpereEvent.OK");
            sd_journal_send("REDFISH_MESSAGE_ID=%s", redfishMsgId.c_str(),
                            "REDFISH_MESSAGE_ARGS=%s", messageStr.c_str(),
                            NULL);
        }
        else
        {
            /* Create an Ampere Warning SEL event */
            std::string messageStr = FWUpdateStatusStr[updateStatus] + " with " +
                FWUpdateTypeStr[updateType];
            std::string redfishMsgId("OpenBMC.0.1.AmpereWarning.Warning");
            sd_journal_send("REDFISH_MESSAGE_ID=%s", redfishMsgId.c_str(),
                            "REDFISH_MESSAGE_ARGS=%s,%s",
                            "Firmware In-band Update Status",
                            messageStr.c_str(), NULL);
        }
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        return ipmi::responseCommandDisabled();
    }

    return ipmi::responseSuccess();
}

/** @brief implements set Host Firmware Revision command
 *  @param - ctx - shared_ptr to an IPMI context struct
 *  @param - Host FW Revision data bytes
 *  @returns IPMI completion code: 0x00: success
 */
ipmi::RspType<uint8_t> ipmiSetHostFWRevision(ipmi::Context::ptr ctx,
                                             uint8_t fwMajor, uint8_t fwMinor,
                                             uint8_t fwAux1st, uint8_t fwAux2nd,
                                             uint8_t fwAux3rd, uint8_t fwAux4th)
{
    ipmi::ChannelInfo chInfo;

    try {
        getChannelInfo(ctx->channel, chInfo);
    }
    catch (sdbusplus::exception_t& e) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiSetHostFWRevision: Failed to get Channel Info",
            phosphor::logging::entry("MSG: %s", e.description()));
        return ipmi::responseUnspecifiedError();
    }
    if (chInfo.mediumType !=
        static_cast<uint8_t>(ipmi::EChannelMediumType::smbusV20)) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiSetHostFWRevision: Error - supported only in SSIF interface");
        return ipmi::responseCommandNotAvailable();
    }

    try
    {
        auto bus = getSdBus();
        try
        {
            std::vector<uint8_t> dataIn;
            uint8_t i;
            std::string hostFWRevision = "";
            char hexStr[3];

            /* Convert Host Firmware Revision to string format */
            dataIn = {fwMajor, fwMinor, fwAux4th, fwAux3rd, fwAux2nd, fwAux1st};

            for (i = 0; i < dataIn.size(); i++)
            {
                sprintf(hexStr, "%02x", dataIn[i]);
                hostFWRevision = hostFWRevision + hexStr;
                if (i == 0 || i == 1)
                    hostFWRevision += ".";
            }
            /* Set Host Firmware Revision to D-bus */
            ipmi::setDbusProperty(*bus, hostFWService, hostFWObject, hostFWInf,
                                  "Version", hostFWRevision);

            /* Store Host Firmware Revision to file */
            std::ofstream hostFwFile(hostFwRevisionFs.c_str());
            hostFwFile << hostFWRevision;
            hostFwFile.close();
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("ipmiSetHostFWRevision: can't set property");
        }
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
}

void registerOEMFunctions() __attribute__((constructor));
void registerOEMFunctions()
{
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::ampere::netFnAmpere,
                          ipmi::general::cmdSyncRtcTime,
                          ipmi::Privilege::Admin, ipmiSyncRTCTimeToBMC);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::ampere::netFnAmpere,
                          ipmi::general::cmdUartSW, ipmi::Privilege::Admin,
                          ipmiDocmdConfigureUartSwitch);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::ampere::netFnAmpere,
                          ipmi::general::cmdScpRead, ipmi::Privilege::User,
                          ipmiDocmdScpReadRegisterMap);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::ampere::netFnAmpere,
                          ipmi::general::cmdScpWrite, ipmi::Privilege::Admin,
                          ipmiDocmdScpWriteRegisterMap);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::ampere::netFnAmpere,
                          ipmi::general::cmdEditBmcMacAdr, ipmi::Privilege::Admin,
                          ipmiDocmdSetMacAddress);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::ampere::netFnAmpere,
                          ipmi::general::cmdGetFanControlStatus,
                          ipmi::Privilege::User, ipmiGetFanControlStatus);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::ampere::netFnAmpere,
                          ipmi::general::cmdSetFanControlStatus,
                          ipmi::Privilege::Admin, ipmiSetFanControlStatus);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::ampere::netFnAmpere,
                          ipmi::general::cmdSetFanSpeed, ipmi::Privilege::Admin,
                          ipmiSetFanSpeed);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::ampere::netFnAmpere,
                          ipmi::general::cmdSetFWInbandUpdateStatus,
                          ipmi::Privilege::Admin, ipmiSetFWInbandUpdateStatus);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::ampere::netFnAmpere,
                          ipmi::general::cmdSetHostFWRevision,
                          ipmi::Privilege::Admin, ipmiSetHostFWRevision);
}
