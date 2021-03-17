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
#include <ipmid/api.hpp>
#include <sdbusplus/message.hpp>
#include <sdbusplus/server/interface.hpp>

struct IpmbResponse
{
    uint8_t address;
    uint8_t netFn;
    uint8_t rqLun;
    uint8_t rsSA;
    uint8_t seq;
    uint8_t rsLun;
    uint8_t cmd;
    uint8_t completionCode;
    std::vector<uint8_t> data;

    IpmbResponse(uint8_t address, uint8_t netFn, uint8_t rqLun, uint8_t rsSA,
                 uint8_t seq, uint8_t rsLun, uint8_t cmd,
                 uint8_t completionCode, std::vector<uint8_t>& inputData);

    void ipmbToi2cConstruct(uint8_t* buffer, size_t* bufferLength);
};

/** @class Bridging
 *
 *  @brief Implement commands to support IPMI bridging.
 */
class Bridging
{
  public:
    Bridging() = default;
    std::size_t getResponseQueueSize();

    void clearResponseQueue();
    void insertMessageInQueue(IpmbResponse msg);
    IpmbResponse getMessageFromQueue();
    void eraseMessageFromQueue();

  private:
    std::vector<IpmbResponse> responseQueue;
};
