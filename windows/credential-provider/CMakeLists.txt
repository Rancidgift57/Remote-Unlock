cmake_minimum_required(VERSION 3.20)
project(RemoteUnlockCredentialProvider LANGUAGES CXX)

if (NOT MSVC)
    message(FATAL_ERROR "This project must be built with MSVC (Visual Studio) — "
                         "Credential Providers require the Windows COM/credentialprovider.h headers.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(RemoteUnlockCredentialProvider SHARED
    DllMain.cpp
    ClassFactory.cpp
    RemoteUnlockProvider.cpp
    RemoteUnlockCredential.cpp
    RemoteUnlockCredentialProvider.def
)

target_link_libraries(RemoteUnlockCredentialProvider PRIVATE
    Secur32.lib
    Credui.lib
    Advapi32.lib
    Ole32.lib
    Shlwapi.lib
)

target_compile_definitions(RemoteUnlockCredentialProvider PRIVATE
    UNICODE _UNICODE
)

# Credential provider DLLs conventionally live in System32 once registered;
# install.ps1 copies the built DLL there and calls regsvr32 — you do not
# need to set the output path here for that to work, this just controls
# where the build drops the freshly-compiled file.
set_target_properties(RemoteUnlockCredentialProvider PROPERTIES
    OUTPUT_NAME "RemoteUnlockCredentialProvider"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
