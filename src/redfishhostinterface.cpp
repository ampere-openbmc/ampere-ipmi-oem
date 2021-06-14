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

static inline auto response(uint8_t cc)
{
    return std::make_tuple(cc, std::nullopt);
}

static inline auto responseParmNotSupported()
{
    return response(creBootstrapDisabled);
}

/** @brief implementes the get random password
 *  @param[in] len - length of password.
 *  @returns password
 */
std::string getRandomPassword(int len)
{
    std::string possibleCharacters = "abcdefghijklmnopqrstuvwxyz";
    std::string upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::string numbers = "0123456789";
    std::string specialChars = "!@#$%^&*";
    srand((unsigned) time(0));
    std::random_device rd;
    std::mt19937 engine(rd());
    std::uniform_int_distribution<> dist(0, possibleCharacters.size()-1);
    std::string ret;
    ret += upperChars[rand() % upperChars.length()];
    ret += numbers[rand() % numbers.length()];
    ret += specialChars[rand() % specialChars.length()];
    /* -3 for adding one upper char, one number, one special char above */
    for(int i = 0; i < len - 3; i++){
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

/** @brief implementes the get redfish host authentication command
 *  @param[in] ctx - shared_ptr to an IPMI context struct
 *  @param[in] bootstrapControl - Disable credential bootstrapping control
 *  @returns ipmi completion code.
 */
ipmi::RspType<std::vector<uint8_t>> /* Output data */
    ipmiOemAmpereCreBootstrap(ipmi::Context::ptr ctx, uint8_t bootstrapControl)
{
    ipmi::ChannelInfo chInfo;
    uint8_t maxChUsers = 0, enabledUsers = 0, fixedUsers = 0;
    std::string userName = "obmcRedfish"; /* Unique user name */
    std::string password;
    uint8_t passwordLen;
    char buffer[bootstrapAccLen] = {};
    uint8_t userId;
    ipmi::PrivAccess privAccess = {0};
    ipmi::UsersTbl* userData;
    std::vector<uint8_t> dataOut;
    uint8_t userCnt;

    try {
        getChannelInfo(ctx->channel, chInfo);
    }
    catch (sdbusplus::exception_t& e) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOemAmpereCreBootstrap: Failed to get Channel Info",
            phosphor::logging::entry("MSG: %s", e.description()));
        return ipmi::responseUnspecifiedError();
    }
    if (chInfo.mediumType !=
        static_cast<uint8_t>(ipmi::EChannelMediumType::smbusV20)) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOemAmpereCreBootstrap: Error - supported only in SSIF "
            "interface");
        return ipmi::responseCommandNotAvailable();
    }

    /* Calculate the number of users in the system */
    userData = ipmi::getUserAccessObject().getUsersTblPtr();
    for (size_t usrIndex = 1; usrIndex <= maxUsers; ++usrIndex) {
        if (userData->user[usrIndex].userInSystem){
            userCnt++;
        }
    }
    if (userCnt < maxUsers) {
        if(bootstrapControl == creBootstrapEnabled) {
            if(bootstrapCtlDisable) {
                return responseParmNotSupported();
            } else {
                /* Find the user ID empty to set the user name
                 * User index 1 is reserved for root user, starts with 2
                 */
                for (size_t usrIndex = 2; usrIndex <= (userCnt + 1); ++usrIndex) {
                    std::string curName =
                        reinterpret_cast<char*>(userData->user[usrIndex].userName);
                    if (curName.empty()) {
                        userId = usrIndex;
                        break;
                    }
                }
                /* Set user name */
                ipmi::ipmiUserSetUserName(userId, (userName + std::to_string(userId)));
                /* Get the password length */
                passwordLen = getPasswordLen();
                do {
                    /* Generate and set the password until pass the password policy */
                    password = getRandomPassword(passwordLen);
                } while (ipmi::ipmiUserSetUserPassword(userId, password.c_str()) != 0);
                /* Set user priv */
                privAccess.privilege = PRIVILEGE_ADMIN;
                ipmi::ipmiUserSetPrivilegeAccess(
                    static_cast<uint8_t>(userId), defaultChannelNum, privAccess, 0);
                /* Enable user */
                ipmi::ipmiUserUpdateEnabledState(userId, enableUser);
            }
        } else {
            bootstrapCtlDisable = true;
            return responseParmNotSupported();
        }
    } else {
        log<level::ERR>("Invalid User ID - Out of range");
        return responseParmNotSupported();
    }

    /* Respond data */
    memcpy(buffer, userName.c_str(), userName.length());
    memcpy(buffer + maxPasswordSize, password.c_str(), password.length());
    dataOut.assign(buffer, buffer + bootstrapAccLen);

    return ipmi::responseSuccess(dataOut);
}

void registerOemAmpereFunctions() __attribute__((constructor));
void registerOemAmpereFunctions()
{
    ipmi::registerGroupHandler(ipmi::prioOpenBmcBase,
                               ipmi::ampere::groupExtIdRedfish,
                               ipmi::general::cmdGetBootstrapAccoutCre,
                               ipmi::Privilege::User,
                               ipmiOemAmpereCreBootstrap);
}
