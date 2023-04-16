cmake_minimum_required(VERSION 3.0.0)
project(TrafficSniffer VERSION 0.1.0)

include(CTest)
enable_testing()

include(FetchContent)

FetchContent_Declare(googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        SOURCE_DIR ${CMAKE_SOURCE_DIR}/google/googletest
        GIT_TAG main)
FetchContent_MakeAvailable(googletest)

FetchContent_Declare(PcapPlusPlus
        GIT_REPOSITORY https://github.com/seladb/PcapPlusPlus.git
        SOURCE_DIR ${CMAKE_SOURCE_DIR}/PcapPlusPlus
        GIT_TAG master)
FetchContent_MakeAvailable(PcapPlusPlus)

# FetchContent_Declare(libpcap
#         GIT_REPOSITORY https://github.com/the-tcpdump-group/libpcap
#         SOURCE_DIR ${CMAKE_SOURCE_DIR}/libpcap
#         GIT_TAG master)
# FetchContent_MakeAvailable(libpcap)


FetchContent_Declare(gflags
        GIT_REPOSITORY https://github.com/gflags/gflags.git
        SOURCE_DIR ${CMAKE_SOURCE_DIR}/gflags
        GIT_TAG master)
FetchContent_MakeAvailable(gflags)


FetchContent_Declare(glog
        GIT_REPOSITORY https://github.com/google/glog.git
        SOURCE_DIR ${CMAKE_SOURCE_DIR}/glog
        GIT_TAG master)
FetchContent_MakeAvailable(glog)


file(GLOB FILES
        "Headers/*.h"
        "Source/*.cpp"
        )
include_directories(Source)
include_directories(Headers)

add_executable(TrafficSniffer ${FILES})


include(GoogleTest)
include_directories(${googletest_SOURCE_DIR}/googletest/include/gtest)
include_directories(${googletest_SOURCE_DIR}/googlemock/include/gmock)
target_link_libraries(TrafficSniffer 
        gtest_main 
        gtest 
        gmock_main 
        gmock)

target_link_libraries(${PROJECT_NAME} Pcap++ Packet++ Common++ pcap pthread)
#target_link_libraries(${PROJECT_NAME} pcap)
target_link_libraries(${PROJECT_NAME} gflags)
target_link_libraries(${PROJECT_NAME} glog)



set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
