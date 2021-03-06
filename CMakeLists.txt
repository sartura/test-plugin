CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")
set(PLUGIN 0 CACHE BOOL "Build a plugin.")

PROJECT(sysrepo-plugin-dt-test)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 -Wall")

set(SOURCES
	src/test.c)

# git SHA1 hash
execute_process(COMMAND
  git describe --always --abbrev=40
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  OUTPUT_VARIABLE GIT_SHA1
  ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)

# by default set to older version for backward compatibility
set(SYSREPO_LESS_0_7_5 ON CACHE BOOL "Sysrepo version older than 0.7.5")

# get sysrepo version
find_package(PkgConfig)
if (PKG_CONFIG_FOUND)
    execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} "--modversion" "sysrepo" OUTPUT_VARIABLE SYSREPO_VERSION)
    if(SYSREPO_VERSION)
        # strip new line from string
        string(STRIP ${SYSREPO_VERSION} SYSREPO_VERSION)
        if(${SYSREPO_VERSION} VERSION_GREATER_EQUAL "0.7.5")
            set(SYSREPO_LESS_0_7_5 OFF)
        endif()
    endif()
endif()

# generate version.h
configure_file("${PROJECT_SOURCE_DIR}/src/version.h.in" "${PROJECT_SOURCE_DIR}/src/version.h" ESCAPE_QUOTES @ONLY)

if(PLUGIN)
	add_library(${CMAKE_PROJECT_NAME} MODULE ${SOURCES})
	install(TARGETS ${CMAKE_PROJECT_NAME} DESTINATION lib)
else()
	add_executable(${CMAKE_PROJECT_NAME} ${SOURCES})
	install(TARGETS ${CMAKE_PROJECT_NAME} DESTINATION bin)
endif()

set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES OUTPUT_NAME ${CMAKE_PROJECT_NAME} PREFIX "")

# dependencies - sysrepo
find_package(SYSREPO REQUIRED)
target_link_libraries(${CMAKE_PROJECT_NAME} ${SYSREPO_LIBRARIES})
include_directories(${SYSREPO_INCLUDE_DIRS})
