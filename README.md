# Ampere OpenBMC IPMI OEM Command Specification

This document describes detailed IPMI commands for original equipment
manufacturers (OEMs) who are designing systems based on reference designs for
Ampere Computing® ARM 64-bit multi-core processors.

Below table shows supported IPMI OEM commands

| Command name                          | NetFn |  Cmd  |
| ------------------------------------- | :---: | :---: |
| Set BMC MAC address                   | 0x3c  | 0x01  |
| Get Fan Speed Control Override Status | 0x3c  | 0x02  |
| Set Fan Speed Control Override        | 0x3c  | 0x03  |
| Set FAN Speed                         | 0x3c  | 0x04  |
| Set SoC Power Limit                   | 0x3c  | 0x11  |
| Get SoC Power Limit                   | 0x3c  | 0x12  |
| Trigger Host Firmware Crash Dump      | 0x3c  | 0x15  |
| Get SCP Register Value                | 0x3c  | 0x17  |
| Get SCP Register Value                | 0x3c  | 0x18  |
| Set DRAM Max Throttle Enable          | 0x3c  | 0x1e  |
| Get DRAM Max Throttle Enable          | 0x3c  | 0x1f  |
| Set Scan Dump Mode                    | 0x3c  | 0x25  |
| Get Scan Dump Mode                    | 0x3c  | 0x26  |
| Set Host Firmware Revision            | 0x3c  | 0xf0  |
| Set Firmware in-band update status    | 0x3c  | 0xf6  |
| Time Change Notification              | 0x3c  | 0xf9  |

## Set BMC MAC Address (0x3c 0x01)

The command sets the BMC MAC address for the Reduced Gigabit Media-Independent
Interface (RGMII) and writes to the Field Replaceable Unit (FRU). This OEM
command supports these cases:

- Rewrite new BMC MAC address if the FRU already has the right MAC address
  format in Board Extra 1.
- Create Board Extra and write the new BMC MAC address if the FRU does not have
  Board Extra information (except when Board Information Area does not have
  enough space for it).
- Rewrite the new BMC MAC address if the FRU contains an invalid MAC address
  format in Board Extra 1 (except when Board Information Area does not have
  enough space for it).

Request

| Byte(s) | Data                   |
| :-----: | ---------------------- |
|   1-6   | MAC Address byte 1 - 6 |

Response

| Byte(s) | Data                                |
| :-----: | ----------------------------------- |
|    1    | Completion Code <br/> 0x00: Success |
|    2    | Written byte count                  |

Example: write new MAC Address `70:E2:84:8F:E3:56`

```
$ ipmitool raw 0x3c 0x01 0x70 0xE2 0x84 0x8F 0xE3 0x56
```

Note: The Ampere-formatted FRU defines a Custom Board Info Field of 17 bytes
“XX:XX:XX:XX:XX:XX” for MAC address in the Board Information Area. This FRU
content should be flashed to the FRU EEPROM before running this command;
otherwise, it may fail.

## Get Fan Speed Control Override Status (0x3C 0x02)

The command gets the thermal control operational status.

Request: None

Response

| Byte(s) | Data                                                                                             |
| :-----: | ------------------------------------------------------------------------------------------------ |
|    1    | Completion Code <br/> 0x00: Success <br/> CC_UNSPECIFIED_ERR = Cannot get thermal control status |
|    2    | Thermal Control operational status <br/> 0x00 = Enabled <br/> 0x01 = Disabled                    |

## Set Fan Speed Control Override (0x3c 0x03)

The command sets the thermal control operational status. When thermal control is
disabled, all fans under thermal control run at the current duty cycle. Thermal
control is initialized with a predefined duty cycle for all fans that may vary
between platforms. Individual chassis fan speeds can be changed using the Set
Fan Speed command. This setting is lost after a BMC reset and the default
thermal control status (enabled) is restored.

Request

| Byte(s) | Data                                                                                  |
| :-----: | ------------------------------------------------------------------------------------- |
|    1    | Thermal control operational status to be set <br/> 0x00 = Enable <br/> 0x01 = Disable |

Response

| Byte(s) | Data                                                                          |
| :-----: | ----------------------------------------------------------------------------- |
|    1    | Completion Code <br/> 0x00: Success                                           |
|    2    | Thermal control operational status <br/> 0x00 = Enabled <br/> 0x01 = Disabled |

## Set FAN Speed (0x3c 0x04)

The command sets the Pulse Width Modulation (PWM) duty cycle of a cooling fan.
Thermal control must be disabled (using the Set Fan Speed Control Override
command) before executing this command.

Request

| Byte(s) | Data                                             |
| :-----: | ------------------------------------------------ |
|    1    | FAN number <br/> 0: FAN0 <br/> 1: FAN1 <br/> ... |
|    2    | PWM duty cycle to be set (1-100)                 |

Response

| Byte(s) | Data                                                                                                                                                                                           |
| :-----: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|    1    | Completion Code <br/> 0x00: Success                                                                                                                                                            |
|    2    | Fan speed change result <br/> 0x00 = Success <br/> 0x01 = Error: Invalid fan number <br/> 0x02 = Cannot set fan speed because thermal control is not disabled <br/> 0xFF = Set fan speed error |

Note: Mapping between fan number and fans on the system depends upon the system
design

## Set SoC Power Limit (0x3c 0x11)

The command sets the SoC power limit.

Note: The supported power limit values can vary depending upon the specific
platform.

Request

| Byte(s) | Data                               |
| :-----: | ---------------------------------- |
|    1    | Configured SoC power limit (upper) |
|    2    | Configured SoC power limit (lower) |

Response

| Byte(s) | Data                                                                                                                                                                                                                                                                                        |
| :-----: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|    1    | Completion Code <br/> 0x00: Success <br/> 0xC9 = Input value is out of range (less than the minimum TDP power or greater than the maximum TDP power) <br/> 0xD5 = The BMC could not send the data to the host. <br/> 0xD6 = Not supported in this platform. <br/> 0xFF = An error occurred. |

## Get SoC Power Limit (0x3c 0x12)

The command gets the SoC power limit.

Request: None

Response

| Byte(s) | Data                                                                                                                                                                       |
| :-----: | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|    1    | Completion Code <br/> 0x00: Success <br/> 0xD5 = The BMC could not send the data to the host. <br/> 0xD6 = Not supported in this platform. <br/> 0xFF = An error occurred. |
|    2    | Current SoC power limit (upper)                                                                                                                                            |
|    3    | Current SoC power limit (lower)                                                                                                                                            |

## Trigger Host Firmware Crash Dump (0x3c 0x15)

The command sends a request to the Mpro to trigger the “firmware crash dump”
feature, which captures the core and system states along with relevant error
syndrome information.

The “firmware crash dump” feature uses the ACPI Boot Error Record Table (BERT)
to store crash information in persistent storage before a reboot, making it
available in the BERT to UEFI and the OS after the reboot.

Request: None

Response

| Byte(s) | Data                                                                                                                                                                       |
| :-----: | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|    1    | Completion Code <br/> 0x00: Success <br/> 0xD5 = The BMC could not send the data to the host. <br/> 0xD6 = Not supported in this platform. <br/> 0xFF = An error occurred. |

### Get SCP Register Value (0x3c 0x17)

Read value from a specified SCP register offset which returns 2 bytes. Note that
with register offset that have 48 bytes data, the command will return only 2
bytes (the first time returns 2 first bytes, the second time returns 2 next
bytes, ...).

Note: this command is available on Altra-based platform only

Request

| Byte(s) | Data                                                          |
| :-----: | ------------------------------------------------------------- |
|    1    | CPU Index: <br/>0 - CPU at Socket 0,<br/> 1 - CPU at Socket 1 |
|    2    | SCP offset to read                                            |

Response

| Byte(s) | Data                                                      |
| :-----: | --------------------------------------------------------- |
|    1    | Completion Code: <br/>0x00 - Success, <br/>0x01 - Failure |
|    2    | Data byte 0                                               |
|    3    | Data byte 1                                               |

Example: Read the SCP register offset 0x53

```
$ ipmitool raw 0x3c 0x17 0x00 0x53
ef 01
```

### Set SCP Register Value (0x3c 0x18)

Write 2 byte values to the SCP register at a specified offset.

Note: this command is available on Altra-based platform only

Request

| Byte(s) | Data                                                           |
| :-----: | -------------------------------------------------------------- |
|    1    | CPU Index: <br/> 0 - CPU at Socket 0, <br/>1 - CPU at Socket 1 |
|    2    | SCP offset to write                                            |
|    2    | Data byte 0                                                    |
|    3    | Data byte 1                                                    |

Response

| Byte(s) | Data                                                      |
| :-----: | --------------------------------------------------------- |
|    1    | Completion Code: <br/>0x00 - Success, <br/>0x01 - Failure |

Example: Write 0x01EF to SCP register offset 0x53

```
$ ipmitool raw 0x3c 0x18 0x00 0x53 0xEF 0x01
```

## Set DRAM Max Throttle Enable (0x3c 0x1e)

The command sets the state of the DRAM Max Throttle Enable sensor.

Request

| Byte(s) | Data                                                                                     |
| :-----: | ---------------------------------------------------------------------------------------- |
|    1    | DRAM Max Throttle Enable sensor state to be set <br/> 0x00 = Disable <br/> 0x01 = Enable |

Response

| Byte(s) | Data                                                                                                                                                                       |
| :-----: | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|    1    | Completion Code <br/> 0x00: Success <br/> 0xD5 = The BMC could not send the data to the host. <br/> 0xD6 = Not supported in this platform. <br/> 0xFF = An error occurred. |

## Get DRAM Max Throttle Enable (0x3c 0x1f)

The command gets the state of the DRAM Max Throttle Enable sensor.

Request: None

Response

| Byte(s) | Data                                                                                                                                                                       |
| :-----: | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|    1    | Completion Code <br/> 0x00: Success <br/> 0xD5 = The BMC could not send the data to the host. <br/> 0xD6 = Not supported in this platform. <br/> 0xFF = An error occurred. |
|    2    | Current DRAM Max Throttle Enable sensor state <br/> 0x00 = Disable <br/> 0x01 = Enable                                                                                     |

## Set Scan Dump Mode (0x3c 0x25)

The command is used for enabling or disabling Scan Dump mode. If Scan Dump mode
is enabled, the BMC stops all the communication with the host. If Scan Dump mode
is disabled, the BMC restores the communication with the host.

Request

| Byte(s) | Data                                                                                |
| :-----: | ----------------------------------------------------------------------------------- |
|    1    | Enable or disable Scan Dump mode <br/> 0x00 = Disable (Default) <br/> 0x01 = Enable |

Response

| Byte(s) | Data                                                                                                             |
| :-----: | ---------------------------------------------------------------------------------------------------------------- |
|    1    | Completion Code <br/> 0x00: Success <br/> 0xD6 = Not supported in this platform. <br/> 0xFF = An error occurred. |

## Get Scan Dump Mode (0x3c 0x26)

The command gets the state of the Scan Dump mode.

Request: None

Response

| Byte(s) | Data                                                                                                             |
| :-----: | ---------------------------------------------------------------------------------------------------------------- |
|    1    | Completion Code <br/> 0x00: Success <br/> 0xD6 = Not supported in this platform. <br/> 0xFF = An error occurred. |
|    2    | Current Scan Dump mode state <br/> 0x00 = Disable (Default) <br/> 0x01 = Enable                                  |

## Set Host Firmware Revision (0x3c 0xf0)

The command sets the Host Firmware Revision.

Request

|  Byte(s)  | Data                                                                                                                                  |
| :-------: | ------------------------------------------------------------------------------------------------------------------------------------- |
|     1     | Firmware Major Version <br/> 0 = internal builds <br/> 1-127 = Firmware Generation code                                               |
|     2     | Firmware Minor Version <br/> 0 = internal builds <br/> 0-99 = map to SRP Major version (if Firmware Major Version in Byte 1 is not 0) |
| [ 3 .. 6] | Firmware Auxiliary Version (SRP Minor version + SRP Patch version) <br/> Example: 0x00003002 (Minor: 00003, Patch: 002)               |

Response

| Byte(s) | Data                                |
| :-----: | ----------------------------------- |
|    1    | Completion Code <br/> 0x00: Success |

## Set Firmware in-band Update status (0x3c 0xf6)

The command is used to send firmware In-band update status to BMC.

Request

| Byte(s) | Data                                                                                                                                                                                                                 |
| :-----: | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|    1    | Update Status <br/> 0x00 = Update started <br/> 0x01 = Update completed with success <br/> 0x02 = Update completed with failure                                                                                      |
|    2    | Update Type <br/> 0x00 = Update entire Host Firmware <br/> 0x01 = Update RO regions of Host Firmware (preserve RW regions) <br/> 0x02 = Update RO regions of Host Firmware (clear RW regions) <br/> 0x03 = MC Update |

Response

| Byte(s) | Data                                                                    |
| :-----: | ----------------------------------------------------------------------- |
|    1    | Completion Code <br/> 0x00: Success <br/> 0xD6 = Handle command failure |

## Time Change Notification (0x3c 0xf9)

This command is used by the host to notify the BMC for RTC Time Change event.
After receiving this notification, BMC will sync-up BMC system time with RTC
time.

Note: The BMC ignores this time change request if the BMC NTP client is enabled.

Request: None

Response

| Byte(s) | Data                                |
| :-----: | ----------------------------------- |
|    1    | Completion Code <br/> 0x00: Success |
