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
    "/sys/bus/platform/devices/smpro-misc.2.auto/",
    "/sys/bus/platform/devices/smpro-misc.5.auto/",
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

/** @brief get Baseboard FRU's address
 *  @param - busIdx, address of I2C device
 *  @returns - true if successfully, false if fail
 */
static bool getBaseBoardFRUAddr(uint8_t &busIdx, uint8_t &addr)
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
        firstByte = (uint8_t)(addr >> 8);
        secondByte = (uint8_t)(addr & 0xff);

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
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::ampere::netFnAmpere,
                          ipmi::general::cmdEditBmcMacAdr, ipmi::Privilege::User,
                          ipmiDocmdSetMacAddress);
}
