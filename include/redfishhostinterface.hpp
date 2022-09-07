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

std::string service = "xyz.openbmc_project.User.Manager";
std::string object = "/xyz/openbmc_project/user/root";
std::string inf = "xyz.openbmc_project.HostInterface.CredentialBootstrapping";

constexpr uint8_t bootstrapAccLen = 32;
constexpr uint8_t minPasswordSize = 9;
constexpr uint8_t maxPasswordSize = 16;
constexpr uint8_t maxUserNameSize = 16;
constexpr uint8_t maxUsers = 15;
constexpr uint8_t enableUser = 0x01;
constexpr uint8_t defaultChannelNum = 0x1;
constexpr uint8_t creBootstrapEnabled = 0xa5;
constexpr uint8_t creBootstrapDisabled = 0x80;
namespace ipmi
{
namespace ampere
{
constexpr uint8_t groupExtIdRedfish = 0x52;
} // namespace ampere
namespace general
{
constexpr uint8_t cmdGetMngCertFinger = 0x01;
constexpr uint8_t cmdGetBootstrapAccoutCre = 0x02;
} // namespace general
} // namespace ipmi
