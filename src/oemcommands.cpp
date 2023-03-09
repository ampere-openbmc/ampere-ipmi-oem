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
#include <nlohmann/json.hpp>
#include "oemcommands.hpp"
#include <cstdlib>
#include <boost/container/flat_map.hpp>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <dirent.h>
#include <fstream>
#include <iostream>
#include <utility>

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

/*
 * The Power Limit configuration, it includes Power Limit configuration of SOC
 * and DIMM ...
 *   - SoC configuration is stored in "SoC" property.
 *   - DIMM configuration is stored in "DIMM" property.
 */
static nlohmann::json powerLimitJsonData;

constexpr static const char* fruDeviceServiceName =
    "xyz.openbmc_project.FruDevice";

constexpr static const char* chassisTypeRackMount = "23";
constexpr static const char* pldmService = "xyz.openbmc_project.PLDM";
constexpr static const char* pldmSensorValInterface =
    "xyz.openbmc_project.Sensor.Value";
constexpr static const char* pldmSensorValPro = "Value";
constexpr static const char* pldmSensorMaxValPro = "MaxValue";
constexpr static const char* pldmSensorMinValPro = "MinValue";

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
[[maybe_unused]] static bool getBaseBoardFRUAddr(uint16_t &busIdx, uint8_t &addr)
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
                    busIdx = (uint16_t)std::get<uint32_t>(busProperty->second);
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
static bool getRawFruData(uint16_t busIdx, uint8_t addr, std::vector<uint8_t> &fruData)
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
    bool shiftFlag = false; /*If shifting is needed*/
    uint32_t boardInfoAreaOffset = fruData[fru::commonHeader::boardOffset] * 8;
    uint32_t boardInfoAreaLength = fruData[boardInfoAreaOffset + 1] * 8;
    uint8_t  checkSumVal = 0;
    uint32_t fieldOffset, shiftOffset = 0;
    int shiftSpace = 0; /*The byte length (signed) that the remaining fruData will be shifted by*/
    char macAddressStr[fru::board::macAddressLength + 1];
    std::vector<uint8_t> shiftBuffer; /*Buffer to temporarily save data to be shifted*/

    /*
     * Update MAC address at first custom field of Board Information Area.
     */
    if(boardInfoAreaOffset != 0)
    {
        /*
         * The Board Manufacturer type/length byte is stored
         * at byte 0x06 of Board area.
         */
        fieldOffset = boardInfoAreaOffset + fru::board::manuNameOffset;
        /*
         * Scan all 5 predefined fields of Board area to jump to
         * first Custom field.
         */
        for(uint32_t i = 0; i < fru::board::predefinedFieldNum; i++)
        {
            fieldOffset += (fruData[fieldOffset] & fru::fieldLengthByteMask) + 1;
        }

        shiftOffset = fieldOffset;

        if (fruData[fieldOffset] != fru::endOfFieldByte)  // not C1 - not EndOfField
        {
            uint8_t boardExtraOneFieldLength = fruData[fieldOffset] & fru::fieldLengthByteMask;
            if (!boardExtraOneFieldLength)
            {
                /* Board Extra 1 field length is 0: add MAC address and transit the data from the 2nd Board Extra field */
                shiftOffset++;
                shiftFlag = true;
            }
            else if (boardExtraOneFieldLength != fru::board::macAddressLength)
            {
                /*
                * MAC address in Board Extra 1 is invalid:
                * Add MAC address and transit the data from the new shift offset
                * which is the byte next to the end of the board extra fields
                * (padding fields are not included); The invalid field will be overriden;
                */
                shiftOffset += boardExtraOneFieldLength + 1;
                shiftFlag = true;
            }
        }
        else
        {
            /* There is no Board Extra field: add MAC address and transit the data */
            shiftFlag = true;
        }
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
        "FRU does not include Board Information Area");
        return retVal;
    }
    if (shiftFlag)
    {
        shiftSpace = fru::board::macAddressLength  + 1 - (shiftOffset - fieldOffset);
        shiftBuffer.assign(fruData.begin() + shiftOffset, fruData.end());
        /*Resize fruData vector to the end of MAC address field*/
        fruData.resize(fieldOffset + fru::board::macAddressLength + 1);
    }

    /* Update the Board Extra 1 field type/length byte */
    fruData[fieldOffset] = fru::board::macAddressLength | fru::fieldTypeMask;
    sprintf(macAddressStr, "%02X:%02X:%02X:%02X:%02X:%02X", macAddress[0], macAddress[1], macAddress[2], macAddress[3], macAddress[4], macAddress[5]);
    /*
    * Update 17 bytes of MAC address information
    */
    for (uint32_t i=0; i < fru::board::macAddressLength; i++)
    {
        fruData[fieldOffset + 1 + i] = macAddressStr[i];
    }

    if (shiftFlag)
    {
        /* shiftSpace has to be divisible by 8 */
        if (shiftSpace % 8)
        {
            /*Number of bytes to be removed to compensate shiftSpace*/
            uint32_t shiftRedundancy = shiftSpace >= 0 ? shiftSpace % 8 : 8 - std::abs(shiftSpace % 8);
            uint32_t zeroCount = 0, boardInfoAreaRemainingLength = boardInfoAreaLength - (shiftOffset - boardInfoAreaOffset);
            uint8_t paddingOffset = 0;
            if (shiftBuffer[paddingOffset] != fru::endOfFieldByte)
            {
                /*
                 * There are likely more than 1 board extra fields
                 * Look for the end of Board Extra fields
                 */
                while (shiftBuffer[paddingOffset] != 0xc1)
                {
                    paddingOffset += (shiftBuffer[paddingOffset] & fru::fieldLengthByteMask) + 1;
                }
                paddingOffset++;
            }

            /* Enlist the zero elements for shiftRedundancy compensation */
            zeroCount = boardInfoAreaRemainingLength - paddingOffset - 1;
            if (zeroCount >= shiftRedundancy)
            {
                shiftBuffer.erase(shiftBuffer.begin() + paddingOffset, shiftBuffer.begin() + paddingOffset + shiftRedundancy);
                shiftSpace -= shiftRedundancy;
            }
            /* Use zero padding if shift redundancy can not be compensated */
            else
            {
                /*Number of bytes to be added to complement shiftSpace*/
                uint32_t shiftPadding = shiftSpace >= 0 ? 8 - (shiftSpace % 8) : std::abs(shiftSpace);
                shiftSpace += shiftPadding;
                /*Pad zero to the padding field of Board Info Area*/
                shiftBuffer.insert(shiftBuffer.begin() + boardInfoAreaRemainingLength - 1, shiftPadding, 0x00);
            }
        }

        /* Re-calculate Board Info Area length
        Board Info Area Start offset stays the same */
        boardInfoAreaLength += shiftSpace;
        fruData[boardInfoAreaOffset + 1] = (uint8_t)boardInfoAreaLength/8;

        uint32_t productInfoAreaOffset = fruData[fru::commonHeader::productOffset]*8;
        if (productInfoAreaOffset)
        {
            /* Re-calculate Product Info Area Starting Offset */
            fruData[fru::commonHeader::productOffset] += shiftSpace/8;
        }

        uint32_t multiRecAreaOffset = fruData[fru::commonHeader::multiRecOffset]*8;
        if (multiRecAreaOffset)
        {
            /* Re-calculate Multi-Record Area Starting Offset */
            fruData[fru::commonHeader::multiRecOffset] += shiftSpace/8;
        }
        /*
        * Re-caculate the checksum of Common Header Area.
        */
        if (productInfoAreaOffset || multiRecAreaOffset)
        {
            for(uint32_t i = 0; i < fru::commonHeader::length - 1; i++)
            {
                checkSumVal += fruData[i];
            }
            checkSumVal = ~checkSumVal + 1;
            fruData[fru::commonHeader::length - 1] = checkSumVal;
        }

        /* Re-insert the shiftBuffer to the fruData vector */
        fruData.insert(fruData.end(), shiftBuffer.begin(), shiftBuffer.end());
    }
    /*
    * Re-caculate the checksum of Board Information Area.
    */
    checkSumVal = 0;
    for(uint32_t i = 0; i < boardInfoAreaLength - 1; i++)
    {
        checkSumVal += fruData[boardInfoAreaOffset + i];
    }
    checkSumVal = ~checkSumVal + 1;
    fruData[boardInfoAreaOffset + boardInfoAreaLength - 1] = checkSumVal;

    retVal = true;
    return retVal;
}

/** @brief write FRU data to EEPROM
 *  @param - busIdx and address of I2C device.
 *         - fruData: FRU data
 *  @returns - true if successfully, false if fail
 */
static bool writeFruData(uint16_t busIdx, uint8_t addr, std::vector<uint8_t> &fruData)
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

/**
 *  @brief Parse SoC/DIMM power limit configuration
 */
static void parsePowerLimitCfg()
{
    const static std::string pwrLimitCfgFile =
                "/usr/share/ipmi-providers/power_limit.json";
    std::ifstream cfgFile(pwrLimitCfgFile);

    if (!cfgFile.is_open())
    {
        log<level::INFO>("Can not open the Power Limit configuration file");
        return;
    }

    try
    {
        powerLimitJsonData = nlohmann::json::parse(cfgFile, nullptr, false);
    }
    catch (const nlohmann::json::parse_error& e)
    {
        log<level::ERR>("Can not parse the Power Limit configuration file");
    }
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
    std::optional<std::uint16_t> addr;

    if (cpuIndex >= scpRWPath.size()) {
        return responseFailure();
    }
    addr = scpReadRegisterMap(scpRWPath[cpuIndex], offsetR);
    if (addr == std::nullopt) {
        return responseFailure();
    }

    return ipmi::responseSuccess((uint8_t)(addr.value() & 0xff),
                                 (uint8_t)(addr.value() >> 8));
}

/** @brief implements ipmi oem command write scp register
 *  @param - cpuIndex, offsetRead and data write byte 0/1
 *  @returns - Fail or Success.
 */
ipmi::RspType<> ipmiDocmdScpWriteRegisterMap(uint8_t cpuIndex, uint8_t offsetW,
                                             uint8_t lowByte, uint8_t highByte)
{
    if (cpuIndex >= scpRWPath.size()) {
        return responseFailure();
    }
    if (!scpWriteRegisterMap(scpRWPath[cpuIndex], offsetW,
                            (((uint16_t)lowByte) | ((uint16_t)highByte << 8))))
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
    uint16_t busIdx = 0;
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

/** @brief implements check ampere_pldm_effecter_trigger.sh script is exist
 *  @param - None
 *  @returns IPMI completion code: 0x00: exist, 0x01: Not exist.
 */
static bool checkPldmEffecterTriggerScriptExist()
{
    /* Check ampere_pldm_effecter_trigger.sh script is exist */
    if (!access(pldmEffecterTriggerScript.c_str(), F_OK))
        return 0;
    else
        return 1;
}

/** @brief implements Ampere IPMI OEM Command Trigger Host Firmware Crash Dump
 *  @param - none
 *  @returns IPMI completion code: 0x00: Success
 *                                       0xD6 = This platform does not support
 *                                       0xFF: Error
 */
ipmi::RspType<uint8_t> ipmiTriggerHostFWCrashDump()
{
    int bertTriggerStt;
    std::string cmd;
    try
    {
        /* Check ampere_pldm_effecter_trigger.sh script is exist */
        if (checkPldmEffecterTriggerScriptExist() == fileNotExists)
        {
            log<level::ERR>("Error: ampere_pldm_effecter_trigger.sh "
                "script is not exist");
            return ipmi::responseCommandDisabled();
        }

        /* Call ampere_pldm_effecter_trigger.sh script trigger crash dump.
         * This script will trigger BERT error by setting value 2 to the
         * S0_Effecter_201
         */
        cmd = pldmEffecterTriggerScript + " -s 0 BERTTrigger";
        bertTriggerStt = system(cmd.c_str());
        if (WEXITSTATUS(bertTriggerStt) == responseError)
        {
            log<level::ERR>("Error: Can not Trigger BERT");
            return ipmi::responseUnspecifiedError();
        }
    }
    catch(const std::exception& e)
    {
        log<level::ERR>(e.what());
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
}

/**
 *  @brief Implement Set SoC power limit command
 *
 *  @param[in] upper - Configured SoC power limit (upper)
 *  @param[in] lower - Configured SoC power limit (lower)
 *
 *  @return IPMI completion code
 *      - Competetion code:
 *          0x00: Success
 *          0xC7: Request Data length is invalid.
 *          0xC9: Input value is out of range (greater or lesser than Socket
 *                TDP).
 *          0xD5: The BMC could not send the data to the host.
 *          0xD6: This platform does not support.
 *          0xFF: An error occurs.
 */
static ipmi::RspType<> setSoCPowerLimit(
                                       [[maybe_unused]]ipmi::Context::ptr ctx,
                                       uint8_t upper,
                                       uint8_t lower
                                     )
{
    ipmi::Cc completeCode = ipmi::ccSuccess;
    uint16_t pwrLimit = ((uint16_t)upper << 8) | (uint16_t)lower;
    bool supportFlg = false;

    /*
     * The SoC power limit is configured in "SoC" property
     */
    if (!powerLimitJsonData.is_discarded())
    {
        /*
         * Depend on the platform, geting SoC power limit can be implemented by
         * different solutions such as PLDM, SCP ...
         * This function should be updated when new solution is provided.
         */

        /*
         * Set power limit via PLDM's sensors
         */
        if ((powerLimitJsonData.contains("SoC")) && 
            (powerLimitJsonData.at("SoC").contains("pldm")))
        {
            supportFlg = true;
            auto pldmSensors = powerLimitJsonData.at("SoC").at("pldm");
            auto sdBus = getSdBus();

            if (pldmSensors.is_array())
            {
                /*
                    * Each PLDM sensor has 2 properties: 
                    *     - objectPath: D-bus object path
                    *     - requiredFlag: this sensor is mandatory or not
                    */
                for (const auto& entity : pldmSensors)
                {
                    std::string ojctPath;
                    bool flag = true;
                    
                    try
                    {
                        ojctPath = entity.at("objectPath").get<std::string>();
                        flag = entity.at("requiredFlag").get<bool>();
                    }
                    catch (const std::exception& e)
                    {
                        log<level::ERR>(
                                "Can not parse power limit configuration data");
                        completeCode = ipmi::ccUnspecifiedError;
                        break;
                    }

                    try
                    {
                        /*
                         * Check the limit range of the sensor, if the
                         * min/max value is "nan" then skip checking
                         */
                        double maxVal = std::get<double>(
                                ipmi::getDbusProperty(*sdBus, pldmService,
                                ojctPath.c_str(), pldmSensorValInterface,
                                pldmSensorMaxValPro));

                        double minVal = std::get<double>(
                                ipmi::getDbusProperty(*sdBus, pldmService,
                                ojctPath.c_str(), pldmSensorValInterface,
                                pldmSensorMinValPro));

                        if ((!std::isnan(maxVal) &&
                                ((uint16_t)maxVal < pwrLimit)) ||
                            (!std::isnan(minVal) &&
                                ((uint16_t)minVal > pwrLimit)))
                        {
                            completeCode = ipmi::ccParmOutOfRange;
                            break;
                        }

                        ipmi::setDbusProperty(*sdBus, pldmService,
                            ojctPath.c_str(), pldmSensorValInterface,
                            pldmSensorValPro, (double)pwrLimit);
                    }
                    catch (const std::exception& e)
                    {
                        /*
                         * If the setting dbus property are fail and this is
                         * a mandatory sensor then request will be stopped.
                         */
                        if (true == flag)
                        {
                            log<level::ERR>(
                                "Error: Can not set the power limit");
                            completeCode = ipmi::ccCommandNotAvailable;
                            break;
                        }
                        else
                        {
                            log<level::INFO>(
                                "Infor: Can not set the power limit");
                            continue;
                        }
                    }
                }
            }
        }
    }

    /*
     * This platform does not support any method to set SoC power limit
     */
    if (!supportFlg)
    {
        completeCode = ipmi::ccCommandDisabled;
    }

    return ipmi::response(completeCode);
}

/**
 *  @brief Implement get SoC power limit command
 *
 *  @return IPMI completion code plus response data
 *      - Competetion code:
 *          0x00: Success
 *          0xD5: The BMC could not send the data to the host.
 *          0xD6: This platform does not support.
 *          0xFF: An error occurs.
 *      - Current SoC power limit (upper)
 *      - Current SoC power limit (lower)
 */
static ipmi::RspType<uint8_t, uint8_t> getSoCPowerLimit(ipmi::Context::ptr ctx)
{
    ipmi::Cc completeCode = ipmi::ccSuccess;
    uint16_t pwrLimit = 0;
    bool supportFlg = false;

    /*
     * The SoC power limit is configure in "SoC" property
     */
    if (!powerLimitJsonData.is_discarded())
    {
        /*
         * Depend on the platform, geting SoC power limit can be implemented by
         * different solutions such as PLDM, SCP ...
         * This function should be updated when new solution is provided.
         */

        /*
         * Get power limit via PLDM's sensors
         */
        if ((powerLimitJsonData.contains("SoC")) && 
            (powerLimitJsonData.at("SoC").contains("pldm")))
        {
            supportFlg = true;
            auto pldmSensors = powerLimitJsonData.at("SoC").at("pldm");

            if (pldmSensors.is_array())
            {
                try
                {
                    /*
                     * Each PLDM sensor has 2 properties: 
                     *     - objectPath: D-bus object path
                     *     - requiredFlag: this sensor is mandatory or not
                     */
                    for (const auto& entity : pldmSensors)
                    {
                        std::string ojctPath =
                                    entity.at("objectPath").get<std::string>();
                        bool flag = entity.at("requiredFlag").get<bool>();
                        double dbusVal = 0;
                        boost::system::error_code ec =
                            ipmi::getDbusProperty(ctx, pldmService, 
                                ojctPath.c_str(), pldmSensorValInterface, 
                                pldmSensorValPro, dbusVal);

                        /*
                         * If the setting dbus property are fail and this is a
                         * mandatory sensor then request will be stopped.
                         */
                        if (ec)
                        {
                            if (true == flag)
                            {
                                log<level::ERR>(
                                    "Error: Can not get the power limit");
                                completeCode = ipmi::ccCommandNotAvailable;
                                break;
                            }
                            else
                            {
                                log<level::INFO>(
                                    "Infor: Can not get the power limit");
                                continue;
                            }
                        }

                        /*
                         * When the Power Limit of sensors are different, BMC
                         * indicates this is an error.
                         */
                        if (pwrLimit == 0)
                        {
                            pwrLimit = (uint16_t)dbusVal;
                        }
                        else if (pwrLimit != (uint16_t)dbusVal)
                        {
                            completeCode = ipmi::ccUnspecifiedError;
                            break;
                        }
                    }
                }
                catch (const std::exception& e)
                {
                    completeCode = ipmi::ccUnspecifiedError;
                    log<level::ERR>(
                            "Can not parse power limit configuration data");
                }
            }
        }
    }

    /*
     * This platform does not support any method to get SoC power limit
     */
    if (!supportFlg)
    {
        completeCode = ipmi::ccCommandDisabled;
    }

    if (completeCode != ipmi::ccSuccess)
    {
        return ipmi::response(completeCode);
    }

    return ipmi::response(completeCode, (uint8_t)(pwrLimit >> 8),
                         (uint8_t)(pwrLimit & 0xff));
}

/**
 *  @brief Implement Set DRAM Max Throttle Enable sensor
 *
 *  @param[in] status - the status of sensor
 *                      0x00: Disable
 *                      0x01: Enable
 *
 *  @return IPMI completion code
 *      - Competetion code:
 *          0x00: Success
 *          0xC7: Request Data length is invalid.
 *          0xD5: The BMC could not send the data to the host.
 *          0xD6: This platform does not support.
 *          0xFF: An error occurs.
 */
static ipmi::RspType<> setDRAMMaxThrottleEnable(
                                            ipmi::Context::ptr ctx,
                                            uint8_t status)
{
    ipmi::Cc completeCode = ipmi::ccSuccess;
    bool supportFlg = false;

    if ((status != 0x00) && (status != 0x01))
    {
        return ipmi::response(ipmi::ccUnspecifiedError);
    }

    /*
     * The DRAM Max Throttle Enable option is configured in "DRAM" property
     */
    if (!powerLimitJsonData.is_discarded())
    {
        /*
         * Depend on the platform, seting DRAM Max Throttle Enable can be
         * implemented by different solutions such as PLDM, SCP ...
         * This function could be updated when new method is provided.
         */

        /*
         * Set DRAM Max Throttle Enable via PLDM's sensors
         */
        if ((powerLimitJsonData.contains("DRAM")) &&
            (powerLimitJsonData.at("DRAM").contains("pldm")))
        {
            supportFlg = true;
            auto pldmSensors = powerLimitJsonData.at("DRAM").at("pldm");

            if (pldmSensors.is_array())
            {
                /*
                    * Each PLDM sensor has 2 properties:
                    *     - objectPath: D-bus object path
                    *     - requiredFlag: this sensor is mandatory or not
                    */
                for (const auto& entity : pldmSensors)
                {
                    std::string ojctPath;
                    bool flag = false;

                    try
                    {
                        ojctPath = entity.at("objectPath").get<std::string>();
                        flag = entity.at("requiredFlag").get<bool>();
                    }
                    catch (const std::exception& e)
                    {
                        log<level::ERR>(
                                "Can not parse Json configuration data");
                        completeCode = ipmi::ccUnspecifiedError;
                        break;
                    }

                    boost::system::error_code ec =
                        ipmi::setDbusProperty(ctx, pldmService,
                            ojctPath.c_str(), pldmSensorValInterface,
                            pldmSensorValPro, (double)status);

                    /*
                     * If the setting dbus property are fail and this is a
                     * mandatory sensor then request will be stopped.
                     */
                    if (ec)
                    {
                        if (true == flag)
                        {
                            log<level::ERR>(
                                "Error: Can not set DRAM Max Throttle Enable");
                            completeCode = ipmi::ccCommandNotAvailable;
                            break;
                        }
                        else
                        {
                            log<level::INFO>(
                                "Info: Can not set DRAM Max Throttle Enable");
                            continue;
                        }
                    }
                }
            }
        }
    }

    /*
     * This platform does not support any method to set DRAM Max Throttle Enable
     */
    if (!supportFlg)
    {
        completeCode = ipmi::ccCommandDisabled;
    }

    return ipmi::response(completeCode);
}

/**
 *  @brief Implement get DRAM Max Throttle Enbale command
 *
 *  @return IPMI completion code plus response data
 *      - Competetion code:
 *          0x00: Success
 *          0xD5: The BMC could not send the data to the host.
 *          0xD6: This platform does not support.
 *          0xFF: An error occurs.
 *      - Current DRAM Max Throttle Enale status
 *          0x00: Disable
 *          0x01: Enable
 */
static ipmi::RspType<uint8_t> getDRAMMaxThrottleEnable(ipmi::Context::ptr ctx)
{
    ipmi::Cc completeCode = ipmi::ccSuccess;
    std::optional<uint8_t> dramStatus = std::nullopt;
    bool supportFlg = false;

    /*
     * The DRAM MAX Throttle Enable option is configured in "DRAM" property
     */
    if (!powerLimitJsonData.is_discarded())
    {
        /*
         * Depend on the platform, Geting DRAM Max Throttle Enable can be
         * implemented by different solutions such as PLDM, SCP ...
         * This function could be updated when new method is provided.
         */

        /*
         * Get DRAM Max Throttle Enable via PLDM's sensors
         */
        if ((powerLimitJsonData.contains("DRAM")) &&
            (powerLimitJsonData.at("DRAM").contains("pldm")))
        {
            supportFlg = true;
            auto pldmSensors = powerLimitJsonData.at("DRAM").at("pldm");

            if (pldmSensors.is_array())
            {
                /*
                 * Each PLDM sensor has 2 properties:
                 *     - objectPath: D-bus object path
                 *     - requiredFlag: this sensor is mandatory or not
                 */
                for (const auto& entity : pldmSensors)
                {
                    std::string ojctPath;
                    bool flag = false;

                    try
                    {
                        ojctPath = entity.at("objectPath").get<std::string>();
                        flag = entity.at("requiredFlag").get<bool>();
                    }
                    catch (const std::exception& e)
                    {
                        log<level::ERR>(
                                "Can not parse Json configuration data");
                        completeCode = ipmi::ccUnspecifiedError;
                        break;
                    }

                    double dbusVal = 0;
                    boost::system::error_code ec =
                        ipmi::getDbusProperty(ctx, pldmService,
                            ojctPath.c_str(), pldmSensorValInterface,
                            pldmSensorValPro, dbusVal);

                    /*
                     * If the setting dbus property are fail and this is a
                     * mandatory sensor then request will be stopped.
                     */
                    if (ec)
                    {
                        if (true == flag)
                        {
                            log<level::ERR>(
                                "Error: Can not get DRAM Max Throttle Enable");
                            completeCode = ipmi::ccCommandNotAvailable;
                            break;
                        }
                        else
                        {
                            log<level::INFO>(
                                "Info: Can not get DRAM Max Throttle Enable");
                            continue;
                        }
                    }

                    /*
                     * When the status of sensors are different, BMC
                     * indicates this is an error.
                     */
                    if (dramStatus == std::nullopt)
                    {
                        dramStatus = (uint8_t)dbusVal;
                    }
                    else if (dramStatus != (uint8_t)dbusVal)
                    {
                        completeCode = ipmi::ccUnspecifiedError;
                        break;
                    }
                }
            }
        }
    }

    /*
     * This platform does not support any method to get DRAM MAX Throttle Enable
     */
    if (!supportFlg)
    {
        completeCode = ipmi::ccCommandDisabled;
    }

    if (completeCode != ipmi::ccSuccess)
    {
        return ipmi::response(completeCode);
    }

    return ipmi::response(completeCode, dramStatus.value());
}

void registerOEMFunctions() __attribute__((constructor));
void registerOEMFunctions()
{
    /*
     * Parse power limit configuration
     */
    parsePowerLimitCfg();

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
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::ampere::netFnAmpere,
                          ipmi::general::cmdTriggerHostFWCrashDump,
                          ipmi::Privilege::Admin, ipmiTriggerHostFWCrashDump);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::ampere::netFnAmpere,
                          ipmi::general::cmdSetSoCPowerLimit,
                          ipmi::Privilege::Admin, setSoCPowerLimit);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::ampere::netFnAmpere,
                          ipmi::general::cmdGetSoCPowerLimit,
                          ipmi::Privilege::Admin, getSoCPowerLimit);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::ampere::netFnAmpere,
                          ipmi::general::cmdSetDRAMMaxThrottleEnable,
                          ipmi::Privilege::Admin, setDRAMMaxThrottleEnable);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::ampere::netFnAmpere,
                          ipmi::general::cmdGetDRAMMaxThrottleEnable,
                          ipmi::Privilege::Admin, getDRAMMaxThrottleEnable);
}
