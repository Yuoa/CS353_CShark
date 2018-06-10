# Project Basic Configuration
PROJECT ( "CShark" )
CMAKE_MINIMUM_REQUIRED ( VERSION 2.5 )
SET ( PROJECT_VERSION_MAJOR 1 )
SET ( PROJECT_VERSION_MINOR 2 )
SET ( CMAKE_BUILD_TYPE Release )
SET ( CMAKE_VERBOSE_MAKEFILE false )

# Add libPCAP
LINK_LIBRARIES ( pcap )

# Build Options
ADD_COMPILE_OPTIONS ( -march=x86-64 -Wno-write-strings )
INCLUDE_DIRECTORIES ( include /usr/include.pcap )
SET ( CMAKE_C_FLAGS_DEBUG "-g" )
SET ( CMAKE_CXX_STANDARD 11 )
SET ( CMAKE_CXX_STANDARD_REQUIRED ON )

ADD_EXECUTABLE (
  CShark
  common.hpp
  core.hpp main.core.cpp sub.core.cpp
  dev.hpp get.dev.cpp select.dev.cpp
  gtp.hpp pcap.hpp protocol.pcap.cpp test.pcap.cpp handle.pcap.cpp capture.pcap.cpp analyze.pcap.cpp decap.pcap.cpp
  )
