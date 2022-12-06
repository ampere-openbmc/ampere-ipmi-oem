/*
 * Copyright (c) 2022 Ampere Computing LLC
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
#include <sdbusplus/bus.hpp>

#include <unordered_map>

#define UPDATE_PWR_LIMIT_PRO(bus, oldVl, newVl, pro, val)                      \
    if ((oldVl) != (newVl))                                                    \
    {                                                                          \
        ipmi::setDbusProperty((*bus), pwrLimitService, pwrLimitObjectPath,     \
                              pwrLimitItf, (pro), (val));                      \
    }

using namespace phosphor::logging;

/*
 * Define power limit service, object path, interface and properties
 */
const std::string pwrLimitService = "xyz.openbmc_project.Control.power.manager";
const std::string pwrLimitObjectPath =
    "/xyz/openbmc_project/control/power/manager/limit";
const std::string pwrLimitItf = "xyz.openbmc_project.Control.Power.Limit";
const std::string exceptionProperty = "ExceptionAction";
const std::string activeProperty = "Active";
const std::string pwrLimitProperty = "PowerLimit";
const std::string correctTimeProperty = "CorrectionTime";
const std::string samplingPeriodProperty = "SamplingPeriod";

/*
 * The mapping between ipmi request value and dbus value of exception action
 */
std::unordered_map<uint8_t, std::string> exceptActionTbl = {
    {0x00, "xyz.openbmc_project.Control.Power.Limit.ExceptionActions.NoAction"},
    {0x01,
     "xyz.openbmc_project.Control.Power.Limit.ExceptionActions.HardPowerOff"},
    {0x02, "xyz.openbmc_project.Control.Power.Limit.ExceptionActions.OEM02"},
    {0x03, "xyz.openbmc_project.Control.Power.Limit.ExceptionActions.OEM03"},
    {0x04, "xyz.openbmc_project.Control.Power.Limit.ExceptionActions.OEM04"},
    {0x05, "xyz.openbmc_project.Control.Power.Limit.ExceptionActions.OEM05"},
    {0x06, "xyz.openbmc_project.Control.Power.Limit.ExceptionActions.OEM06"},
    {0x07, "xyz.openbmc_project.Control.Power.Limit.ExceptionActions.OEM07"},
    {0x08, "xyz.openbmc_project.Control.Power.Limit.ExceptionActions.OEM08"},
    {0x09, "xyz.openbmc_project.Control.Power.Limit.ExceptionActions.OEM09"},
    {0x0A, "xyz.openbmc_project.Control.Power.Limit.ExceptionActions.OEM0A"},
    {0x0B, "xyz.openbmc_project.Control.Power.Limit.ExceptionActions.OEM0B"},
    {0x0C, "xyz.openbmc_project.Control.Power.Limit.ExceptionActions.OEM0C"},
    {0x0D, "xyz.openbmc_project.Control.Power.Limit.ExceptionActions.OEM0D"},
    {0x0E, "xyz.openbmc_project.Control.Power.Limit.ExceptionActions.OEM0E"},
    {0x0F, "xyz.openbmc_project.Control.Power.Limit.ExceptionActions.OEM0F"},
    {0x10, "xyz.openbmc_project.Control.Power.Limit.ExceptionActions.OEM10"},
    {0x11, "xyz.openbmc_project.Control.Power.Limit.ExceptionActions.SELLog"}};

static ipmi::RspType<uint16_t, // Reserved for future use
                     uint8_t,  // Exception Actions
                     uint16_t, // Power Limit Requested in Watts
                     uint32_t, // Correction Time Limit in milliseconds
                     uint16_t, // Reserved for future use
                     uint16_t  // Sampling period in seconds
                     >
    dcmiGetPowerLimit(uint16_t)
{
    /*
     * Handle dcmi Get Power limit command
     */
    auto dbus = getSdBus();
    auto pwrLimitProperties = ipmi::getAllDbusProperties(
        *dbus, pwrLimitService, pwrLimitObjectPath, pwrLimitItf);

    if (pwrLimitProperties.empty() ||
        (pwrLimitProperties.find(activeProperty) == pwrLimitProperties.end()) ||
        (pwrLimitProperties.find(exceptionProperty) ==
         pwrLimitProperties.end()) ||
        (pwrLimitProperties.find(pwrLimitProperty) ==
         pwrLimitProperties.end()) ||
        (pwrLimitProperties.find(correctTimeProperty) ==
         pwrLimitProperties.end()) ||
        (pwrLimitProperties.find(samplingPeriodProperty) ==
         pwrLimitProperties.end()))
    {
        return ipmi::responseUnspecifiedError();
    }

    bool actState = std::get<bool>(pwrLimitProperties[activeProperty]);
    uint8_t completeCode = (actState == true) ? 0x00 : 0x80;
    uint16_t powerLimit =
        std::get<uint16_t>(pwrLimitProperties[pwrLimitProperty]);
    uint16_t samplingPeriod =
        std::get<uint16_t>(pwrLimitProperties[samplingPeriodProperty]);
    uint32_t correctTime =
        std::get<uint32_t>(pwrLimitProperties[correctTimeProperty]);
    uint8_t exceptAction = 0xff;
    uint16_t reserved = 0x00;
    std::string exceptActionStr =
        std::get<std::string>(pwrLimitProperties[exceptionProperty]);

    for (const auto& [key, value] : exceptActionTbl)
    {
        if (0 == value.compare(exceptActionStr))
        {
            exceptAction = key;
            break;
        }
    }
    if (exceptAction == 0xff)
    {
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::response(completeCode, reserved, exceptAction, powerLimit,
                          correctTime, reserved, samplingPeriod);
}

static ipmi::RspType<> dcmiSetPowerLimit(uint24_t, // Reserved for future use
                                         uint8_t exceptionAction,
                                         uint16_t pwrLimit,
                                         uint32_t correctTime,
                                         uint16_t, // Reserved for future use
                                         uint16_t samplingPeriod)
{
    /*
     * Handle dcmi Set Power limit command
     */
    uint8_t completeCode = 0x00;
    auto dbus = getSdBus();
    auto pwrLimitProperties = ipmi::getAllDbusProperties(
        *dbus, pwrLimitService, pwrLimitObjectPath, pwrLimitItf);

    if (pwrLimitProperties.empty() ||
        (pwrLimitProperties.find(activeProperty) == pwrLimitProperties.end()) ||
        (pwrLimitProperties.find(exceptionProperty) ==
         pwrLimitProperties.end()) ||
        (pwrLimitProperties.find(pwrLimitProperty) ==
         pwrLimitProperties.end()) ||
        (pwrLimitProperties.find(correctTimeProperty) ==
         pwrLimitProperties.end()) ||
        (pwrLimitProperties.find(samplingPeriodProperty) ==
         pwrLimitProperties.end()))
    {
        return ipmi::responseUnspecifiedError();
    }

    /*
     * Compare current configuration and input value.
     * If they are diffrent then request to update dbus propertis.
     */
    uint16_t currentPwrLimit =
        std::get<uint16_t>(pwrLimitProperties[pwrLimitProperty]);
    uint16_t currentSamplingPeriod =
        std::get<uint16_t>(pwrLimitProperties[samplingPeriodProperty]);
    uint32_t currentCorrectTime =
        std::get<uint32_t>(pwrLimitProperties[correctTimeProperty]);
    uint8_t currentExceptAction = 0xff;
    std::string exceptActionStr =
        std::get<std::string>(pwrLimitProperties[exceptionProperty]);

    for (const auto& [key, value] : exceptActionTbl)
    {
        if (0 == value.compare(exceptActionStr))
        {
            currentExceptAction = key;
            break;
        }
    }
    if ((currentExceptAction == 0xff) ||
        (exceptActionTbl.find(exceptionAction) == exceptActionTbl.end()))
    {
        return ipmi::responseUnspecifiedError();
    }

    /*
     * Request to update dbus propertis.
     */
    UPDATE_PWR_LIMIT_PRO(dbus, currentExceptAction, exceptionAction,
                         exceptionProperty, (exceptActionTbl[exceptionAction]));

    UPDATE_PWR_LIMIT_PRO(dbus, currentPwrLimit, pwrLimit, pwrLimitProperty,
                         pwrLimit);

    UPDATE_PWR_LIMIT_PRO(dbus, currentSamplingPeriod, samplingPeriod,
                         samplingPeriodProperty, samplingPeriod);

    UPDATE_PWR_LIMIT_PRO(dbus, currentCorrectTime, correctTime,
                         correctTimeProperty, correctTime);

    return ipmi::response(completeCode);
}

static ipmi::RspType<> dcmiActivatePowerLimit(uint8_t activate, uint16_t)
{
    /*
     * Handle dcmi Activate/Deactivate Power limit command
     */
    if ((activate != 0) && (activate != 1))
    {
        return ipmi::responseParmOutOfRange();
    }

    auto dbus = getSdBus();
    bool activeState = (activate == 0x01) ? true : false;

    ipmi::setDbusProperty((*dbus), pwrLimitService, pwrLimitObjectPath,
                          pwrLimitItf, activeProperty, activeState);

    return ipmi::responseSuccess();
}

void registerDCMIOverrideFunctions() __attribute__((constructor));
void registerDCMIOverrideFunctions()
{
    ipmi::registerGroupHandler(ipmi::prioOemBase, ipmi::groupDCMI,
                               ipmi::dcmi::cmdGetPowerLimit,
                               ipmi::Privilege::User, dcmiGetPowerLimit);

    ipmi::registerGroupHandler(ipmi::prioOemBase, ipmi::groupDCMI,
                               ipmi::dcmi::cmdSetPowerLimit,
                               ipmi::Privilege::Operator, dcmiSetPowerLimit);

    ipmi::registerGroupHandler(ipmi::prioOemBase, ipmi::groupDCMI,
                               ipmi::dcmi::cmdActDeactivatePwrLimit,
                               ipmi::Privilege::Operator,
                               dcmiActivatePowerLimit);
}
