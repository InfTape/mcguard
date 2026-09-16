cmake_minimum_required(VERSION 3.20)
project(MCGuard LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-D_UNICODE -DUNICODE -D_WIN32_WINNT=0x0A00)

set(SOURCES
    src/main.cpp
    src/util/privilege.cpp
    src/util/string_util.cpp
    src/util/config_loader.cpp
    src/core/process_watcher.cpp
    src/core/wfp_guard.cpp
    src/core/etw_watcher.cpp
    src/core/network_tracker.cpp
    src/core/folder_watcher.cpp
    src/core/module_tracker.cpp
    src/core/correlator.cpp
    src/ui/console_view.cpp
)

add_executable(MCGuard ${SOURCES})

target_include_directories(MCGuard PRIVATE src)

target_link_libraries(MCGuard PRIVATE
    Fwpuclnt
    Advapi32
    tdh
    Ws2_32
    Iphlpapi
    Shell32
    Ole32
    User32
)
