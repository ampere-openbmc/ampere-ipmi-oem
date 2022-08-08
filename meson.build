project(
  'ampere-ipmi-oem',
  'cpp',
  version: '0.1',
  meson_version: '>=0.57.0',
  default_options: [
    'werror=true',
    'warning_level=3',
    'cpp_std=c++20',
  ])

# Project Arguments
cpp = meson.get_compiler('cpp')
add_project_arguments(
  cpp.get_supported_arguments([
    '-DBOOST_ERROR_CODE_HEADER_ONLY',
    '-DBOOST_SYSTEM_NO_DEPRECATED',
    '-DBOOST_ALL_NO_LIB',
    '-DBOOST_NO_RTTI',
    '-DBOOST_NO_TYPEID',
    '-DBOOST_ASIO_DISABLE_THREADS',
    '-DBOOST_COROUTINES_NO_DEPRECATION_WARNING',
    '-Wno-psabi',
    '-Wno-pedantic',
  ]),
  language : 'cpp')

if get_option('mac_address_fru_bus') != 0
  add_project_arguments(
    '-DMAC_ADDRESS_FRU_BUS='+get_option('mac_address_fru_bus').to_string(),
    language : 'cpp')
endif

if get_option('mac_address_fru_addr') != 0
  add_project_arguments(
    '-DMAC_ADDRESS_FRU_ADDR='+get_option('mac_address_fru_addr').to_string(),
    language : 'cpp')
endif

root_inc = include_directories('.', 'include')

# Dependencies
phosphor_logging_dep = dependency('phosphor-logging')
sdbusplus_dep = dependency('sdbusplus', required : false, include_type: 'system')
ipmid_dep = dependency('libipmid')
channellayer_dep = cpp.find_library('channellayer', required: true)
userlayer_dep = cpp.find_library('userlayer', required: true)

zampoemcmds_pre = declare_dependency(
  include_directories: root_inc,
  dependencies: [
    phosphor_logging_dep,
    sdbusplus_dep,
    ipmid_dep,
    channellayer_dep,
    userlayer_dep,
  ])

zampoemcmds_lib = library(
  'zampoemcmds',
  'src/appcommands.cpp',
  'src/bootprogress.cpp',
  'src/bridgingcommands.cpp',
  'src/ipmi_to_redfish_hooks.cpp',
  'src/oemcommands.cpp',
  'src/redfishhostinterface.cpp',
  'src/storagecommands.cpp',
  implicit_include_directories: false,
  dependencies: zampoemcmds_pre,
  version: meson.project_version(),
  override_options: ['b_lundef=false'],
  install: true,
  install_dir: get_option('libdir') / 'ipmid-providers')