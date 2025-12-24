cmake_minimum_required(VERSION 3.16)
project(mpi_pcap_threat_scanner LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BUILD_DASHBOARD "Build lightweight web dashboard server" ON)
option(BUILD_PDC_ANALYZER "Build production-grade PDC PCAP analyzer" ON)
option(BUILD_PDC_GUI "Build NetworkMiner-like GUI for PDC analyzer" ON)

find_package(MPI REQUIRED)

# libpcap (Linux/macOS)
find_path(PCAP_INCLUDE_DIR pcap/pcap.h pcap.h)
find_library(PCAP_LIBRARY NAMES pcap)

if (NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
  message(FATAL_ERROR "libpcap not found. Install libpcap-dev (Debian/Ubuntu) or libpcap-devel (RHEL/Fedora).")
endif()

# Original MPI scanner
add_executable(pcap_scan_mpi
  src/main_mpi.cpp
  src/args.cpp
  src/common.cpp
  src/ioc.cpp
  src/pcap_decode.cpp
  src/scanner.cpp
  src/mpi_gather.cpp
)

target_include_directories(pcap_scan_mpi PRIVATE ${PCAP_INCLUDE_DIR} include)
target_link_libraries(pcap_scan_mpi PRIVATE MPI::MPI_CXX ${PCAP_LIBRARY})

if (UNIX)
  target_link_libraries(pcap_scan_mpi PRIVATE pthread)
endif()

# Production-grade PDC PCAP Analyzer
if (BUILD_PDC_ANALYZER)
  add_executable(pdc_pcap_analyzer
    src/main_pdc_analyzer.cpp
    src/ext_decoder.cpp
    src/ext_scanner.cpp
    src/common.cpp
    src/ioc.cpp
    src/mpi_gather.cpp
  )

  target_include_directories(pdc_pcap_analyzer PRIVATE ${PCAP_INCLUDE_DIR} include)
  target_link_libraries(pdc_pcap_analyzer PRIVATE MPI::MPI_CXX ${PCAP_LIBRARY})

  if (UNIX)
    target_link_libraries(pdc_pcap_analyzer PRIVATE pthread)
  endif()
endif()

if (BUILD_DASHBOARD)
  add_executable(pcap_dashboard
    tools/dashboard/main_dashboard.cpp
    src/common.cpp
  )
  target_include_directories(pcap_dashboard PRIVATE include)
  if (UNIX)
    target_link_libraries(pcap_dashboard PRIVATE pthread)
  endif()
endif()

# NetworkMiner-like GUI for PDC PCAP Analyzer
if (BUILD_PDC_GUI)
  add_executable(pdc_gui
    tools/gui/main_pdc_gui.cpp
  )
  target_include_directories(pdc_gui PRIVATE include)
  if (UNIX)
    target_link_libraries(pdc_gui PRIVATE pthread)
  endif()
endif()

# Unit tests
option(BUILD_TESTING "Build unit tests" OFF)
if (BUILD_TESTING)
  enable_testing()
  find_package(GTest QUIET)
  
  if (GTest_FOUND)
    # Test executables
    add_executable(test_common
      tests/test_common.cpp
      src/common.cpp
    )
    target_include_directories(test_common PRIVATE include)
    target_link_libraries(test_common PRIVATE GTest::gtest GTest::gtest_main)
    if (UNIX)
      target_link_libraries(test_common PRIVATE pthread)
    endif()
    add_test(NAME CommonTests COMMAND test_common)
    
    add_executable(test_ioc
      tests/test_ioc.cpp
      src/ioc.cpp
      src/common.cpp
    )
    target_include_directories(test_ioc PRIVATE include)
    target_link_libraries(test_ioc PRIVATE GTest::gtest GTest::gtest_main)
    if (UNIX)
      target_link_libraries(test_ioc PRIVATE pthread)
    endif()
    add_test(NAME IocTests COMMAND test_ioc)
    
    add_executable(test_aho_corasick
      tests/test_aho_corasick.cpp
    )
    target_include_directories(test_aho_corasick PRIVATE include)
    target_link_libraries(test_aho_corasick PRIVATE GTest::gtest GTest::gtest_main)
    if (UNIX)
      target_link_libraries(test_aho_corasick PRIVATE pthread)
    endif()
    add_test(NAME AhoCorasickTests COMMAND test_aho_corasick)
    
    add_executable(test_space_saving
      tests/test_space_saving.cpp
    )
    target_include_directories(test_space_saving PRIVATE include)
    target_link_libraries(test_space_saving PRIVATE GTest::gtest GTest::gtest_main)
    if (UNIX)
      target_link_libraries(test_space_saving PRIVATE pthread)
    endif()
    add_test(NAME SpaceSavingTests COMMAND test_space_saving)
    
    add_executable(test_protocol_types
      tests/test_protocol_types.cpp
    )
    target_include_directories(test_protocol_types PRIVATE include)
    target_link_libraries(test_protocol_types PRIVATE GTest::gtest GTest::gtest_main)
    if (UNIX)
      target_link_libraries(test_protocol_types PRIVATE pthread)
    endif()
    add_test(NAME ProtocolTypesTests COMMAND test_protocol_types)
    
    message(STATUS "Unit tests enabled - GTest found")
  else()
    message(WARNING "GTest not found, unit tests will not be built")
  endif()
endif()
