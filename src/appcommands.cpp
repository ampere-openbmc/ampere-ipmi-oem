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

#include <phosphor-logging/log.hpp>
#include <ipmid/api.hpp>
#include <ipmid/sessiondef.hpp>
#include <ipmid/sessionhelper.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>

auto ipmiAppGetSiCapabilities(uint8_t sysIfcType)
    -> ipmi::RspType<uint8_t, uint8_t, uint8_t, uint8_t>
{
    uint8_t reserved = 0x00;
    uint8_t tranSupport;
    uint8_t inputMsgSize;
    uint8_t outputMsgSize;
    switch (sysIfcType & 0xF)
    {
        case 0:
            //SSIF
            // multi-part read/write supported. Start, Middle, and End
            // transactions supported. PEC supported.
            tranSupport = 0x88;
            inputMsgSize = 0xff;
            outputMsgSize = 0xff -3; //minus 3 is to drop len, netfn, lun, cmd
            break;
        case 1:
        case 2:
            //KCS or SMIC
            tranSupport = 0x00;
            inputMsgSize = 0xff;
            break;
        default:
            return ipmi::responseInvalidFieldRequest();
    }

    return ipmi::responseSuccess(reserved, tranSupport, inputMsgSize,
                                 outputMsgSize);
}

void registerAppFunctions() __attribute__((constructor));
void registerAppFunctions()
{
    // <Get System Interface Capabilities>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdGetSystemIfCapabilities,
                          ipmi::Privilege::User, ipmiAppGetSiCapabilities);

}


