cmake_minimum_required(VERSION 3.20)

project(smithproxy_gui VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(MICROHTTPD REQUIRED IMPORTED_TARGET libmicrohttpd)
pkg_check_modules(CURL REQUIRED IMPORTED_TARGET "libcurl>=7.85")
find_package(nlohmann_json 3.11 REQUIRED CONFIG)

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/external/lmhpp/include/lmhttpd.hpp")
    message(FATAL_ERROR "lmhpp is missing; run: git submodule update --init")
endif()

option(SMITHPROXY_GUI_BUILD_FRONTEND "Build the frontend with pnpm" ON)
set(SMITHPROXY_GUI_FRONTEND_DIR "${CMAKE_CURRENT_BINARY_DIR}/frontend")

if(SMITHPROXY_GUI_BUILD_FRONTEND)
    find_program(NODE_EXECUTABLE node REQUIRED)
    find_program(PNPM_EXECUTABLE pnpm REQUIRED)
    execute_process(
        COMMAND "${NODE_EXECUTABLE}" --version
        OUTPUT_VARIABLE NODE_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE
        COMMAND_ERROR_IS_FATAL ANY
    )
    if(NOT NODE_VERSION MATCHES "^v(2[2-9]|[3-9][0-9])\\.")
        message(FATAL_ERROR "Smithproxy GUI frontend requires Node.js 22 or newer; found ${NODE_VERSION}")
    endif()
    get_filename_component(NODE_DIRECTORY "${NODE_EXECUTABLE}" DIRECTORY)
    file(GLOB_RECURSE FRONTEND_SOURCES CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/src/*.ts"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/*.css"
    )
    add_custom_command(
        OUTPUT "${SMITHPROXY_GUI_FRONTEND_DIR}/index.html"
        COMMAND "${CMAKE_COMMAND}" -E env "PATH=${NODE_DIRECTORY}:$ENV{PATH}"
                "${PNPM_EXECUTABLE}" install --frozen-lockfile --prefer-offline
        COMMAND "${CMAKE_COMMAND}" -E env "PATH=${NODE_DIRECTORY}:$ENV{PATH}"
                "${PNPM_EXECUTABLE}" run build --outDir "${SMITHPROXY_GUI_FRONTEND_DIR}"
        DEPENDS
            ${FRONTEND_SOURCES}
            "${CMAKE_CURRENT_SOURCE_DIR}/index.html"
            "${CMAKE_CURRENT_SOURCE_DIR}/package.json"
            "${CMAKE_CURRENT_SOURCE_DIR}/pnpm-lock.yaml"
            "${CMAKE_CURRENT_SOURCE_DIR}/tsconfig.json"
            "${CMAKE_CURRENT_SOURCE_DIR}/vite.config.ts"
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        COMMENT "Building Smithproxy GUI frontend"
        VERBATIM
    )
    add_custom_target(smithproxy-gui-frontend ALL
        DEPENDS "${SMITHPROXY_GUI_FRONTEND_DIR}/index.html")
endif()

add_library(smithproxy_gui_core
    src/backend/audit_store.cpp
    src/backend/config.cpp
    src/backend/config_snapshot.cpp
    src/backend/draft_store.cpp
    src/backend/json.cpp
    src/backend/live_sessions.cpp
    src/backend/neighbor_metrics.cpp
    src/backend/operational_alerts.cpp
    src/backend/path.cpp
    src/backend/runtime_metrics.cpp
    src/backend/smithproxy_client.cpp
    src/backend/tls_metrics.cpp
)
target_include_directories(smithproxy_gui_core PUBLIC src/backend)
target_link_libraries(smithproxy_gui_core PUBLIC PkgConfig::CURL nlohmann_json::nlohmann_json)
target_compile_options(smithproxy_gui_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(smithproxy-gui
    src/backend/http_server.cpp
    src/backend/main.cpp
)
target_include_directories(smithproxy-gui PRIVATE
    src/backend
    external/lmhpp/include
)
target_compile_definitions(smithproxy-gui PRIVATE
    SMITHPROXY_GUI_DEFAULT_ASSET_ROOT="${SMITHPROXY_GUI_FRONTEND_DIR}"
)
target_link_libraries(smithproxy-gui PRIVATE smithproxy_gui_core PkgConfig::MICROHTTPD)
target_compile_options(smithproxy-gui PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
if(TARGET smithproxy-gui-frontend)
    add_dependencies(smithproxy-gui smithproxy-gui-frontend)
endif()

include(CTest)
if(BUILD_TESTING)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_executable(backend_unit_tests tests/backend_unit.cpp)
    target_link_libraries(backend_unit_tests PRIVATE smithproxy_gui_core)
    target_compile_options(backend_unit_tests PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME backend_unit_tests COMMAND backend_unit_tests)
    if(SMITHPROXY_GUI_BUILD_FRONTEND)
        set(SMITHPROXY_GUI_TEST_ASSET_DIR "${SMITHPROXY_GUI_FRONTEND_DIR}")
    else()
        set(SMITHPROXY_GUI_TEST_ASSET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/frontend")
    endif()
    add_test(NAME backend_integration_tests
        COMMAND Python3::Interpreter "${CMAKE_CURRENT_SOURCE_DIR}/tests/backend_integration.py"
                "$<TARGET_FILE:smithproxy-gui>" "${SMITHPROXY_GUI_TEST_ASSET_DIR}")
    set_tests_properties(backend_integration_tests PROPERTIES TIMEOUT 20)
    add_test(NAME config_coverage_tests
        COMMAND Python3::Interpreter "${CMAKE_CURRENT_SOURCE_DIR}/tests/config_coverage.py"
                "${CMAKE_CURRENT_SOURCE_DIR}/docs/CONFIG_COVERAGE.json")
endif()
