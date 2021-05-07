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

#include <random>
#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <user_channel/user_layer.hpp>
#include <user_channel/user_mgmt.hpp>
#include <phosphor-logging/log.hpp>
#include <iostream>
#include "commandutils.hpp"
#include "redfishhostinterface.hpp"

using namespace phosphor::logging;

/** @brief implementes the get random password
 *  @param[in] len - length of password.
 *  @returns password
 */
std::string getRandomPassword(int len)
{
    std::string possibleCharacters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*";
    std::random_device rd;
    std::mt19937 engine(rd());
    std::uniform_int_distribution<> dist(0, possibleCharacters.size()-1);
    std::string ret = "";
    for(int i = 0; i < len; i++){
        int index = dist(engine);
        ret += possibleCharacters[index];
    }
    return ret;
}

/** @brief implementes the get the length of password
 *  @param[in] none
 *  @returns the length of the password
 */
uint8_t getPasswordLen()
{
    std::random_device rd;
    std::mt19937 gen(rd());
    /* Password lenth between 9 to 16 characters long */
    std::uniform_int_distribution<> distr(minPasswordSize, maxPasswordSize);
    return distr(gen);
}

/** @brief implementes convert the characters to string
 *  @param[in] character
 * @param[in] size the size of the input characters
 *  @returns the string
 */
std::string convertToString(char* a, int size)
{
    int i;
    std::string s = "";
    for (i = 0; i < size; i++) {
        s = s + a[i];
    }
    return s;
}

/** @brief implementes the get redfish host authentication command
 *  @param[in] netfn - specifies netfn.
 *  @param[in] cmd   - specifies cmd number.
 *  @param[in] request - pointer to request data.
 *  @param[in, out] dataLen - specifies request data length, and returns
 * response data length.
 *  @param[in] context - ipmi context.
 *  @returns ipmi completion code.
 */
ipmi_ret_t ipmiOemAmpereCreBootstrap(ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_request_t request,
                                     ipmi_response_t response, ipmi_data_len_t dataLen,
                                     ipmi_context_t context)
{
    uint8_t maxChUsers = 0, enabledUsers = 0, fixedUsers = 0;
    std::string userName = "obmcRedfish"; /* Unique user name */
    std::string password;
    uint8_t passwordLen;
    std::string userPassword;
    uint8_t resSize = 32;
    char buffer[resSize] = {};
    uint8_t userId;
    uint8_t retStatus;
    bool validUser;

    RedfishHostInterfaceReq* req = static_cast<RedfishHostInterfaceReq*>(request);
    size_t reqLength = *dataLen;
    *dataLen = 0;

    if (reqLength != sizeof(*req)){
        log<level::DEBUG>("Invalid Length");
        return ipmi::ccReqDataLenInvalid;
    }

    /* Calculate the number of users in the system */
    retStatus = ipmi::ipmiUserGetAllCounts(maxChUsers, enabledUsers, fixedUsers);
    if (retStatus != ipmi::ccSuccess){
        return ipmi::ccResponseError;
    }
    userId = enabledUsers + 1;
    validUser = ipmi::getUserAccessObject().isValidUserName(userName);
    /* Check the existing user name in the system, if the redfish host interface
     * user name does not exist. Create the new one.
    */
    if(validUser) {
        if (req->bootstrapControl != creBootstrapEnabled) {
            log<level::DEBUG>("Disable invalid user name");
            return ipmi::ccResponseError;
        }
        /* Set user name */
        ipmi::ipmiUserSetUserName(userId, userName);

        /* Get the password length */
        passwordLen = getPasswordLen();
        do {
            /* Generate and set the password until pass the password policy */
            password = getRandomPassword(passwordLen);

        } while (ipmi::ipmiUserSetUserPassword(userId, password.c_str()) != 0);

        /* Set user priv */
        ipmi::PrivAccess privAccess = {0};
        privAccess.privilege = PRIVILEGE_ADMIN;
        ipmi::ipmiUserSetPrivilegeAccess(static_cast<uint8_t>(userId), defaultChannelNum,
                                            privAccess, 0);
    } else {
        /* Find the UserID folow the existing user name */
        userId = ipmi::getUserAccessObject().getUserId(userName);
        /* Get password from existing user name */
        password = ipmi::ipmiUserGetPassword(userName);
    }

    /* Enable and disable user name folow the credentials bootstrap Control parameter */
    if (req->bootstrapControl == creBootstrapEnabled)
        ipmi::ipmiUserUpdateEnabledState(userId, enableUser);
    else {
        ipmi::ipmiUserUpdateEnabledState(userId, disableUser);
        return creBootstrapDisabled;
    }

    /* Respond data */
    RedfishHostInterfaceResp* resp = static_cast<RedfishHostInterfaceResp*>(response);
    memcpy(buffer, userName.c_str(), userName.length());
    memcpy(buffer + maxPasswordSize, password.c_str(), password.length());
    userPassword = convertToString(buffer, resSize);
    std::fill(reinterpret_cast<uint8_t*>(resp),
            reinterpret_cast<uint8_t*>(resp) + sizeof(*resp), 0);
    userPassword.copy(reinterpret_cast<char*>(resp),
                sizeof(*resp), 0);
    *dataLen = sizeof(*resp);

    return ipmi::ccSuccess;
}

void registerOemAmpereFunctions() __attribute__((constructor));
void registerOemAmpereFunctions()
{
    ipmi_register_redfish_host_inf(ipmi::ampere::netFnDmtf, ipmi::general::cmdGetBootstrapAccoutCre,
                           NULL, ipmiOemAmpereCreBootstrap, PRIVILEGE_OPERATOR);
}
