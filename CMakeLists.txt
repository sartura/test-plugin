CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")
set(PLUGIN 0 CACHE BOOL "Build a plugin.")

PROJECT(sysrepo-plugin-dt-test)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 -Wall")

set(SOURCES
	src/test.c)

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
