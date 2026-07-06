cmake_minimum_required(VERSION 3.15...4.3)
project(${SKBUILD_PROJECT_NAME} LANGUAGES C)

find_package(
  Python
  COMPONENTS Interpreter Development.Module
  REQUIRED)

find_package(OpenSSL COMPONENTS SSL)

python_add_library(ssl_workaround MODULE src/ssl_workaround.c WITH_SOABI)

target_link_libraries(ssl_workaround PRIVATE OpenSSL::SSL)

install(TARGETS ssl_workaround DESTINATION ${SKBUILD_PROJECT_NAME})
