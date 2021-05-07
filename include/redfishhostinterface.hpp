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

constexpr uint8_t bootstrapAccLen = 32;
constexpr uint8_t minPasswordSize = 9;
constexpr uint8_t maxPasswordSize = 16;
constexpr uint8_t maxUserNameSize = 16;
constexpr uint8_t maxConsecutiveChars = 3;
constexpr uint8_t disableUser = 0x00;
constexpr uint8_t enableUser = 0x01;
constexpr uint8_t defaultChannelNum = 0x1;
constexpr uint8_t groupExtId = 0x52;
constexpr uint8_t creBootstrapEnabled = 0xa5;
constexpr uint8_t creBootstrapDisabled = 0x80;

/** @struct RedfishHostInterfaceReq
 *
 *  Structure for get Redfish Host Authentication request command
 */
struct RedfishHostInterfaceReq
{
    uint8_t bootstrapControl;
} __attribute__((packed));

/** @struct RedfishHostInterfaceResp
 *
 *  Structure for get Redfish Host Authentication response command
 */
struct RedfishHostInterfaceResp
{
    uint8_t bootstrapAcc[bootstrapAccLen];
} __attribute__((packed));

namespace ipmi
{
namespace ampere
{
constexpr uint8_t netFnDmtf = 0x2c;
} // namespace ampere
namespace general
{
constexpr uint8_t cmdGetMngCertFinger = 0x01;
constexpr uint8_t cmdGetBootstrapAccoutCre = 0x02;
} // namespace general
} // namespace ipmi
