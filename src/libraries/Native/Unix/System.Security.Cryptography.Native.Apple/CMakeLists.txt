project(System.Security.Cryptography.Native.Apple C)

execute_process(
    COMMAND xcrun --find swiftc
    OUTPUT_VARIABLE SWIFTC_PATH
    OUTPUT_STRIP_TRAILING_WHITESPACE)

include(${CMAKE_CURRENT_LIST_DIR}/extra_libs.cmake)

set(NATIVE_LIBS_EXTRA)
append_extra_cryptography_apple_libs(NATIVE_LIBS_EXTRA)

set(NATIVECRYPTO_SOURCES
    pal_aead.c
    pal_digest.c
    pal_ecc.c
    pal_hmac.c
    pal_keyagree.c
    pal_keychain.c
    pal_random.c
    pal_rsa.c
    pal_sec.c
    pal_seckey.c
    pal_signverify.c
    pal_ssl.c
    pal_symmetric.c
    pal_trust.c
    pal_x509.c
    pal_x509chain.c
)

if (CLR_CMAKE_TARGET_IOS)
    add_definitions(-DTARGET_IOS)
endif()

if (CLR_CMAKE_TARGET_TVOS)
    add_definitions(-DTARGET_TVOS)
endif()

if (GEN_SHARED_LIB)
    execute_process(COMMAND
        ${SWIFTC_PATH}
        -emit-object
        -parse-as-library
        -sdk ${CMAKE_OSX_SYSROOT}
        -o ${CMAKE_CURRENT_LIST_DIR}/pal_cryptokit.o
        ${CMAKE_CURRENT_LIST_DIR}/pal_cryptokit.swift
         RESULT_VARIABLE SWIFTC_RESULT
    )

    if (NOT SWIFTC_RESULT EQUAL "0")
        message(FATAL_ERROR "Swift compilation failed.")
    endif()

    add_library(System.Security.Cryptography.Native.Apple
        SHARED
        ${NATIVECRYPTO_SOURCES}
        ${VERSION_FILE_PATH}
    )
endif()

add_library(System.Security.Cryptography.Native.Apple-Static
    STATIC
    ${NATIVECRYPTO_SOURCES}
    entrypoints.c
)

set_target_properties(System.Security.Cryptography.Native.Apple-Static PROPERTIES OUTPUT_NAME System.Security.Cryptography.Native.Apple CLEAN_DIRECT_OUTPUT 1)

if (GEN_SHARED_LIB)
    target_link_libraries(System.Security.Cryptography.Native.Apple
        -L/usr/lib/swift -Wl,-rpath,/usr/lib/swift
        ${CMAKE_CURRENT_LIST_DIR}/pal_cryptokit.o
        ${NATIVE_LIBS_EXTRA}
    )
endif()

if (GEN_SHARED_LIB)
    install_with_stripped_symbols (System.Security.Cryptography.Native.Apple PROGRAMS .)
endif()

install (TARGETS System.Security.Cryptography.Native.Apple-Static DESTINATION ${STATIC_LIB_DESTINATION})
