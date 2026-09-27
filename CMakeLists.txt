cmake_minimum_required(VERSION 3.15)
project(snap7_demo CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "This project only provides prebuilt snap7 binaries for 64-bit Windows (win64).")
endif()

set(SNAP7_ROOT ${CMAKE_SOURCE_DIR}/third_party/snap7)
set(SNAP7_INCLUDE_DIR ${SNAP7_ROOT}/include)
set(SNAP7_LIB_DIR ${SNAP7_ROOT}/lib/win64)
set(SNAP7_DLL ${SNAP7_LIB_DIR}/snap7.dll)
set(SNAP7_IMPLIB ${SNAP7_LIB_DIR}/libsnap7.dll.a)

if(NOT EXISTS ${SNAP7_IMPLIB})
    message(FATAL_ERROR
        "Missing MinGW import library: ${SNAP7_IMPLIB}\n"
        "Generate it once from the prebuilt snap7.dll with:\n"
        "  gendef ${SNAP7_DLL}\n"
        "  dlltool -d snap7.def -l ${SNAP7_IMPLIB} -D snap7.dll")
endif()

set(NPCAP_SDK_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/third_party/npcap-sdk/Include)

add_executable(SPScomm
    src/main.cpp
    src/npcap_dyn.cpp
    src/profinet_scan.cpp
    src/logger.cpp
)

target_include_directories(SPScomm PRIVATE ${SNAP7_INCLUDE_DIR} ${NPCAP_SDK_INCLUDE_DIR})
target_link_libraries(SPScomm PRIVATE ${SNAP7_IMPLIB} iphlpapi ws2_32)

# Statically link the MinGW runtime so SPScomm.exe runs standalone
# (only snap7.dll needs to sit next to it), without needing MSYS2 on PATH.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_link_options(SPScomm PRIVATE -static-libgcc -static-libstdc++ -static)
endif()

# Keep the exe next to the DLL it needs at runtime.
add_custom_command(TARGET SPScomm POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${SNAP7_DLL} $<TARGET_FILE_DIR:SPScomm>/snap7.dll
)
