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
 * limitations under the License.
 */

#include <systemd/sd-journal.h>

#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/message.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include "commandutils.hpp"
#include "bootprogress.hpp"
#include <iostream>
#include <fstream>
#include <string>

using namespace phosphor::logging;

static inline auto response(uint8_t cc)
{
	return std::make_tuple(cc, std::nullopt);
}

static inline auto responseParmNotSupported()
{
	return response(commandCompletedError);
}

/** @brief Sets the property value of the given object.
 *  @param[in] bus - DBUS Bus Object.
 *  @param[in] service - Dbus service name.
 *  @param[in] objPath - Dbus object path.
 *  @param[in] interface - Dbus interface.
 *  @param[in] property - name of the property.
 *  @param[in] value - value which needs to be set.
 *  @param[out] - none
 */
void setProperty(sdbusplus::bus::bus &bus, const std::string &busName,
		 const std::string &objPath, const std::string &interface,
		 const std::string &property, const postcodeData &value)
{
	std::variant<postcodeData> variantValue = value;
	try {
		auto methodCall =
			bus.new_method_call(busName.c_str(), objPath.c_str(),
					    "org.freedesktop.DBus.Properties",
					    "Set");
		methodCall.append(interface, property, variantValue);
		auto reply = bus.call(methodCall);
	} catch (const std::exception &e) {
		log<level::ERR>("Set properties fail.",
				entry("ERROR = %s", e.what()),
				entry("Object path = %s", objPath.c_str()));
		return;
	}
}

/** @brief Sets the boot progress Post code.
 *  @param[in] state1st - The post code 1st value
 *  @param[in] state2nd - The post code 2nd value
 *  https://github.com/openbmc/phosphor-dbus-interfaces/blob/master/yaml/xyz/
 *  openbmc_project/State/Boot/Raw.interface.yaml#L6
 *  @param[out] - none
 */
void setProgressPostCode(uint64_t state1st, uint8_t state2nd)
{
	postcodeData pcData{ state1st, { state2nd } };
	auto bus = getSdBus();
	try {
		std::string service = "xyz.openbmc_project.State.Boot.Raw";
		std::string object = "/xyz/openbmc_project/state/boot/raw0";
		std::string inf = "xyz.openbmc_project.State.Boot.Raw";
		setProperty(*bus, service, object, inf, "Value", pcData);
	} catch (const std::exception &e) {
		log<level::ERR>("setProgressPostCode: can't set property");
	}
}

uint64_t getCurrentTime()
{
	uint64_t t = 0;
	auto bus = getSdBus();
	try {
		ipmi::Value variant = ipmi::getDbusProperty(
			*bus, timeMngservice, timeObject, timeInf, "Elapsed");
		t = std::get<uint64_t>(variant);
	} catch (const std::exception &e) {
		log<level::ERR>("getCurrentTime: can't get property");
	}

	return t;
}

/** @brief Update the Redfish BootProgress.LastState property
 *  @param[in] s - The LastState value
 *  @param[out] - none
 */
void updateProgressLaststateDbus(std::string s)
{
	auto bus = getSdBus();
	try {
		std::string bpValue =
			"xyz.openbmc_project.State.Boot.Progress.ProgressStages." +
			s;
		ipmi::setDbusProperty(*bus, bpService, bpObject, bpInf,
				      "BootProgress", bpValue);
	} catch (const std::exception &e) {
		log<level::ERR>(
			"updateProgressLaststateDbus: can't set property");
	}
}

/** @brief Update the Redfish BootProgress.BootProgressLastUpdate property
 *  @param[in] t - The BootProgressLastUpdate value
 *  @param[out] - none
 */
void updateProgressLastStateTimeDbus(uint64_t t)
{
	auto bus = getSdBus();
	try {
		ipmi::setDbusProperty(*bus, bpService, bpObject, bpInf,
				      "BootProgressLastUpdate", t);
	} catch (const std::exception &e) {
		log<level::ERR>(
			"updateProgressLastStateTimeDbus: can't set property");
	}
}

/** @brief Get the the boot progress code record to string value
 *  @param[in] - The boot progress code record
 *  @param[out] - The boot progress code record in string format
 */
std::string bootProgressRecordtoStr(uint8_t codeType, uint8_t reserved1st,
				    uint8_t reserved2nd, uint8_t severity,
				    uint8_t operation1st, uint8_t operation2nd,
				    uint8_t subClass, uint8_t codeClass,
				    uint8_t instance)
{
	std::vector<uint8_t> dataIn;
	uint8_t i;
	std::string s = "0x";
	char hexStr[3];

	/* Get the boot progress code record to string value
     * The value of the BootProgress.OemLastState like
     * "OemLastState" : "0x010000000010010000"
     */
	dataIn = { codeType, reserved1st,  reserved2nd,
		   severity, operation1st, operation2nd,
		   subClass, codeClass,	   instance };

	for (i = 0; i < dataIn.size(); i++) {
		sprintf(hexStr, "%02x", dataIn[i]);
		s = s + hexStr;
	}

	return s;
}

/** @brief Store the boot progress code record to file system for the get boot
 * progress command.
 *  @param[in] - The boot progress code record
 *  @param[out] - none
 */
void storeBootProgressFile(uint8_t codeType, uint8_t reserved1st,
			   uint8_t reserved2nd, uint8_t severity,
			   uint8_t operation1st, uint8_t operation2nd,
			   uint8_t subClass, uint8_t codeClass,
			   uint8_t instance)
{
	std::vector<uint8_t> dataIn;
	uint8_t i;
	std::ofstream bpf(bootProgressFs.c_str());
	char hexStr[5];

	/* The boot progress code record is stored in /var/lib/bootprogress file
     * system as format: 0x01 0x02 0x03 0x04 0x5 0x6 0x07 0x08 0x09
     */
	dataIn = { codeType, reserved1st,  reserved2nd,
		   severity, operation1st, operation2nd,
		   subClass, codeClass,	   instance };
	for (i = 0; i < dataIn.size(); i++) {
		sprintf(hexStr, "0x%02x", dataIn[i]);

		if (i == (dataIn.size() - 1))
			bpf << hexStr;
		else
			bpf << hexStr << " ";
	}

	bpf.close();
}

/** @brief implementes the set boot progress command
 *  @param[in] ctx - shared_ptr to an IPMI context struct
 *  @param[in] - 9 bytes of the boot progress code record
 *  @returns ipmi completion code.
 */
ipmi::RspType<uint8_t>
ipmiSendBootProgressCode(ipmi::Context::ptr ctx, uint8_t codeType,
			 uint8_t reserved1st, uint8_t reserved2nd,
			 uint8_t severity, uint8_t operation1st,
			 uint8_t operation2nd, uint8_t subClass,
			 uint8_t codeClass, uint8_t instance)
{
	ipmi::ChannelInfo chInfo;
	std::stringstream stream;
	std::string bpRecordStr;
	std::string message;
	uint64_t lastStateTime = 0;
	uint64_t bpdataIn;
	std::vector<uint8_t> tmp;

	try {
		getChannelInfo(ctx->channel, chInfo);
	} catch (sdbusplus::exception_t &e) {
		phosphor::logging::log<phosphor::logging::level::ERR>(
			"ipmiSendBootProgressCode: Failed to get Channel Info",
			phosphor::logging::entry("MSG: %s", e.description()));
		return ipmi::responseUnspecifiedError();
	}
	if (chInfo.mediumType !=
	    static_cast<uint8_t>(ipmi::EChannelMediumType::smbusV20)) {
		phosphor::logging::log<phosphor::logging::level::ERR>(
			"ipmiSendBootProgressCode: Error - supported only in SSIF "
			"interface");
		return ipmi::responseCommandNotAvailable();
	}

	try {
		/* Store boot progress data record to file system */
		storeBootProgressFile(codeType, reserved1st, reserved2nd,
				      severity, operation1st, operation2nd,
				      subClass, codeClass, instance);

		/* Get boot progress code record to string format */
		bpRecordStr =
			bootProgressRecordtoStr(codeType, reserved1st,
						reserved2nd, severity,
						operation1st, operation2nd,
						subClass, codeClass, instance);

		/* Create EventLog in case byte 1st is ERROR_CODE */
		if (codeType == ERROR_CODE) {
			stream.str("");
			/* Host Processor Error code report */
			if ((codeClass == 0x00) && (subClass == 0x01) &&
			    (operation2nd == 0x10)) {
				stream << hostProcessorEC[operation1st]
				       << std::endl;
				message = stream.str();
				std::string redfishMsgId(
					"OpenBMC.0.1.CPUError");
				sd_journal_send("REDFISH_MESSAGE_ID=%s",
						redfishMsgId.c_str(),
						"REDFISH_MESSAGE_ARGS=%s",
						message.c_str(), NULL);
			}
			/* PCI Error code report */
			else if ((codeClass == 0x02) && (subClass == 0x01) &&
				 (operation2nd == 0x10)) {
				if (operation1st == 0x00) {
					std::string redfishMsgId(
						"OpenBMC.0.1.LegacyPCIPERR");
					sd_journal_send("REDFISH_MESSAGE_ID=%s",
							redfishMsgId.c_str(),
							NULL);
				} else if (operation1st == 0x01) {
					std::string redfishMsgId(
						"OpenBMC.0.1.LegacyPCISERR");
					sd_journal_send("REDFISH_MESSAGE_ID=%s",
							redfishMsgId.c_str(),
							NULL);
				} else {
					return responseParmNotSupported();
				}
			}
			/* DXE Boot service Error code report */
			else if ((codeClass == 0x03) && (subClass == 0x05) &&
				 (operation2nd == 0x10)) {
				std::string redfishMsgId(
					"OpenBMC.0.1.InvalidLoginAttempted");
				sd_journal_send("REDFISH_MESSAGE_ID=%s",
						redfishMsgId.c_str(), NULL);
			} else {
				return responseParmNotSupported();
			}
		} else /* Create Ampere OK event in case byte 1st is PROGRESS_CODE */
		{
			stream.str("");
			std::string bpRecordEventLogStr =
				"Boot progress code: " + bpRecordStr;
			stream << bpRecordEventLogStr << std::endl;
			message = stream.str();
			sd_journal_send( "MESSAGE=%s",
					message.c_str(), "PRIORITY=%i", LOG_INFO, NULL);
		}

		/* Adding to d-bus for support Redfish report
		* Update boot progress to Redfish's LastState attribute to OEM or
		* PCIInit or OSRunning.
		* - As defined in DEN0069C_SBMR_1.1 chapter F.3:
		*   PCI Bus Init: EFI_IO_BUS_PCI | EFI_IOB_PC_INIT
		*   The Redfish BootProgress.LastState will set to PCIInit with raw
		*   data: 0x01 0x00 0x00 0x00 0x00 0x00 0x01 0x02 0x00
		*
		* - As defined in AmpereOne_Boot_Progress_Code spec:
		*   Exit Boot Services: (EFI_SOFTWARE_EFI_BOOT_SERVICE |
		*                        EFI_SW_BS_PC_EXIT_BOOT_SERVICES)
		*   can mapped to OSBootStarted.
		*   data: 0x01 0x00 0x00 0x00 0x19 0x10 0x10 0x03 0x00
		*
		* - Otherwise, setting the BootProgress.LastState to Oem
		*/
		if ((codeType == 0x01) && (severity == 0x00) &&
		    (operation1st == 0x00) && (operation2nd == 0x00) &&
		    (subClass == 0x01) && (codeClass == 0x02))
			updateProgressLaststateDbus("PCIInit");
		if ((codeType == 0x01) && (severity == 0x00) &&
		    (operation1st == 0x19) && (operation2nd == 0x10) &&
		    (subClass == 0x10) && (codeClass == 0x03))
			updateProgressLaststateDbus("OSStart");
		else
			updateProgressLaststateDbus("OEM");

		/* Get the BMC's current time*/
		lastStateTime = getCurrentTime();
		/* Update the boot progress record to BootProgress.LastStateTime
         * This property shall contain the date and time when the last boot
         * state was updated.
         */
		updateProgressLastStateTimeDbus(lastStateTime);

		/* The OemLastState will updated to the PostCodes Boot.Raw:
         * https://github.com/openbmc/phosphor-dbus-interfaces/blob/master/yaml/
         * xyz/openbmc_project/State/Boot/Raw.interface.yaml#L6
         * The type of the Boot.Raw value is struct[uint64,array[byte]]
         * Update the BootProgress code to the Boot.Raw value:
         *  - First 8 bytes to the first element of the Boot.Raw value
         *  - The last one bytes to the last element of the Boot.Raw value
         */
		tmp = { codeType,     reserved1st,  reserved2nd, severity,
			operation1st, operation2nd, subClass,	 codeClass };
		for (auto i : tmp)
			bpdataIn = ((bpdataIn << 8) + i);
		setProgressPostCode(bpdataIn, instance);
	} catch (const std::exception &e) {
		log<level::ERR>(e.what());
		return responseParmNotSupported();
	}

	return ipmi::responseSuccess();
}

/** @brief implementes the get boot progress command
 *  @param[in] ctx - shared_ptr to an IPMI context struct
 *  @param[out] - 9 bytes of the boot progress code record
 *  @returns ipmi completion code.
 */
ipmi::RspType<std::vector<uint8_t> >
ipmiGetBootProgressCode(ipmi::Context::ptr ctx)
{
	ipmi::ChannelInfo chInfo;
	std::vector<uint8_t> dataOut;
	uint8_t i = 0;
	std::string bpStr;
	dataOut.assign(bpRecordSize, 0);

	try {
		getChannelInfo(ctx->channel, chInfo);
	} catch (sdbusplus::exception_t &e) {
		phosphor::logging::log<phosphor::logging::level::ERR>(
			"ipmiGetBootProgressCode: Failed to get Channel Info",
			phosphor::logging::entry("MSG: %s", e.description()));
		return ipmi::responseUnspecifiedError();
	}
	if (chInfo.mediumType !=
	    static_cast<uint8_t>(ipmi::EChannelMediumType::smbusV20)) {
		phosphor::logging::log<phosphor::logging::level::ERR>(
			"ipmiGetBootProgressCode: Error - supported only in SSIF "
			"interface");
		return ipmi::responseCommandNotAvailable();
	}

	try {
		/* Read boot progress data record from the file system */
		std::ifstream bpf(bootProgressFs.c_str());
		if (bpf.fail()) {
			log<level::ERR>("Failed to open file");
			return responseParmNotSupported();
		}

		while (!bpf.eof()) {
			bpf >> bpStr;
			dataOut[i] = stoi(bpStr, nullptr, BASE);
			i++;
		}
		bpf.close();
	} catch (const std::exception &e) {
		log<level::ERR>(e.what());
		return responseParmNotSupported();
	}

	return ipmi::responseSuccess(dataOut);
}

void registerSbmrFunctions() __attribute__((constructor));
void registerSbmrFunctions()
{
	ipmi::registerGroupHandler(ipmi::prioOpenBmcBase,
				   ipmi::ampere::groupExtIpmi,
				   ipmi::general::cmdSendBootProgressCode,
				   ipmi::Privilege::User,
				   ipmiSendBootProgressCode);
	ipmi::registerGroupHandler(ipmi::prioOpenBmcBase,
				   ipmi::ampere::groupExtIpmi,
				   ipmi::general::cmdGetBootProgressCode,
				   ipmi::Privilege::User,
				   ipmiGetBootProgressCode);
}
