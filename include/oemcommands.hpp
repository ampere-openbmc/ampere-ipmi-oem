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

#pragma once
#include <cstdint>

#define BASE 16

constexpr uint8_t responseEnabled = 0x00;
constexpr uint8_t responseFail = 0x01;
constexpr uint8_t responseDisabled = 0x01;
constexpr uint8_t fileNotExists = 0x01;
constexpr uint8_t responseInvalidFanNum = 0x01;
constexpr uint8_t responseSetFanError = 0x02;
std::string fanCtrlScript = "/usr/sbin/ampere_fanctrl.sh";
/* For Firmware In-band update status */
constexpr uint8_t FWUpdateStarted = 0x00;
constexpr uint8_t FWUpdateSuccess = 0x01;
constexpr uint8_t FWUpdateFailure = 0x02;
std::string FWUpdateStatusStr[3] =
    {
        "Update started",
        "Update success",
        "Update failure",
    };
constexpr uint8_t FWUpdateEntireHostFW = 0x00;
constexpr uint8_t FWUpdatePreserveRW = 0x01;
constexpr uint8_t FWUpdateClearRW = 0x02;
std::string FWUpdateTypeStr[3] =
    {
        "entire Host FW",
        "RO regions (preserve RW regions)",
        "RO regions (clear RW regions)",
    };
/* For Host Firmware Revision */
std::string hostFWService = "xyz.openbmc_project.Software.BMC.Updater";
std::string hostFWObject = "/xyz/openbmc_project/software/bios_active";
std::string hostFWInf = "xyz.openbmc_project.Software.Version";
std::string hostFwRevisionFs = "/var/lib/host_fw_revision";
namespace ipmi
{
namespace ampere
{
constexpr uint8_t netFnAmpere = 0x3c;
} // namespace ampere
namespace general
{
constexpr uint8_t cmdEditBmcMacAdr = 0x01;
constexpr uint8_t cmdGetFanControlStatus = 0x02;
constexpr uint8_t cmdSetFanControlStatus = 0x03;
constexpr uint8_t cmdSetFanSpeed = 0x04;
constexpr uint8_t cmdScpRead = 0x17;
constexpr uint8_t cmdScpWrite = 0x18;
constexpr uint8_t cmdUartSW = 0xb0;
constexpr uint8_t cmdSetHostFWRevision = 0xf0;
constexpr uint8_t cmdSetFWInbandUpdateStatus = 0xf6;
constexpr uint8_t cmdSyncRtcTime = 0xf9;
} // namespace general
} // namespace ipmi