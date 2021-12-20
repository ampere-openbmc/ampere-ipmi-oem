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
constexpr uint8_t responseInvalidFanNum = 0x01;
constexpr uint8_t responseSetFanError = 0x02;
std::string fanCtrlScript = "/usr/sbin/ampere_fanctrl.sh";


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
constexpr uint8_t cmdSyncRtcTime = 0xf9;
} // namespace general
} // namespace ipmi