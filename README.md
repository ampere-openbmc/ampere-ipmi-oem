# Ampere IPMI OEM (0x3c)

Below table shows supported IPMI OEM commands

| Command name | NetFn | Cmd |
| --- | :---: | :--: |
| Set BMC MAC address | 0x3c | 0x01 |
| Get SCP Register Value | 0x3c | 0x017 |
| Get SCP Register Value | 0x3c | 0x018 |
| Sync RTC time | 0x3c | 0xf9 |

### Set BMC MAC address

Write new BMC MAC Address into the MB FRU EEPROM at the Custom Board Info field.

Request

| Byte(s) | Data |
| :---: | --- |
| 1-6 | MAC Address byte 1 - 6 |

Response

| Byte(s) | Data |
| :---: | --- |
| 1 | Completion Code </br> 0x00: Success |
| 2 | Written byte count |

Example: write new MAC Address `70:E2:84:8F:E3:56`

```
$ ipmitool raw 0x3c 0x01 0x70 0xE2 0x84 0x8F 0xE3 0x56
```


### Get SCP Register Value

Read value from a specified SCP register offset which returns 2 bytes. Note that with register offset that have 48 bytes data, the command will return only 2 bytes (the first time returns 2 first bytes, the second time returns 2 next bytes, ...).

Request

| Byte(s) | Data |
| :---: | --- |
| 1 | CPU Index: 0 - CPU at Socket 0, 1 - CPU at Socket 1 |
| 2 | SCP offset to read |

Response

| Byte(s) | Data |
| :---: | --- |
| 1 | Completion Code: 0x00 - Success, 0x01 - Failure |
| 2 | Data byte 0 |
| 3 | Data byte 1 |

Example: Read the SCP register offset 0x53

```
$ ipmitool raw 0x3c 0x17 0x00 0x53
ef 01
```

### Set SCP Register Value

Write 2 byte values to the SCP register at a specified offset.

Request

| Byte(s) | Data |
| :---: | --- |
| 1 | CPU Index: 0 - CPU at Socket 0, 1 - CPU at Socket 1 |
| 2 | SCP offset to write |
| 2 | Data byte 0 |
| 3 | Data byte 1 |

Response

| Byte(s) | Data |
| :---: | --- |
| 1 | Completion Code: 0x00 - Success, 0x01 - Failure |

Example: Write 0x01EF to SCP register offset 0x53

```
$ ipmitool raw 0x3c 0x18 0x00 0x53 0xEF 0x01
```

### Sync RTC time

Request BMC to check the new time from RTC. When NTP is disabled, update BMC time using value from RTC. Do nothing when NTP is enabled.

Request: None

Response

| Byte(s) | Data |
| --- | --- |
| 1 | Completion Code: 0x00 - Success |

Example:

```
$ ipmitool raw 0x3c 0xf9
```