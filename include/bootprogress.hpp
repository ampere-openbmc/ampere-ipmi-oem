/*
 * Copyright (c) 2021 Ampere Computing LLC
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
 * limitations under the License
 */

#pragma once
#include <cstdint>
#include <vector>

#include <iostream>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/message.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

using namespace phosphor::logging;

#define BASE 16
#define ERROR_CODE 0x02

using postcodeData = std::tuple<uint64_t, std::vector<uint8_t>>;

std::string hostProcessorEC[14] =
    {
        "Invalid type",
        "Invalid speed",
        "Mismatch detected between two instances",
        "A watchdog timer expired",
        "Instance detected an error during BIST",
        "Instance detected an IERR",
        "An over temperature was detected",
        "Voltage dropped below the low voltage threshold",
        "Voltage surpassed the high voltage threshold",
        "Cache failure",
        "Microcode update failed",
        "Correctable error",
        "Uncorrectable ECC error",
        "No matching microcode update",
    };

std::string bpService = "xyz.openbmc_project.State.Host";
std::string bpObject = "/xyz/openbmc_project/state/host0";
std::string bpInf = "xyz.openbmc_project.State.Boot.Progress";
std::string timeMngservice = "xyz.openbmc_project.Time.Manager";
std::string timeObject = "/xyz/openbmc_project/time/bmc";
std::string timeInf = "xyz.openbmc_project.Time.EpochTime";
std::string bootProgressFs = "/var/lib/bootprogress";

constexpr uint8_t commandCompletedError = 0x80;
constexpr uint8_t bpRecordSize = 9;

namespace ipmi
{
namespace ampere
{
constexpr uint8_t groupExtIpmi = 0xae;
} // namespace ampere
namespace general
{
constexpr uint8_t cmdSendBootProgressCode = 0x02;
constexpr uint8_t cmdGetBootProgressCode = 0x03;
} // namespace general
} // namespace ipmi