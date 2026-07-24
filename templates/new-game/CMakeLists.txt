cmake_minimum_required(VERSION 3.20)

# ============================================================================
# YOUR_GAME_NAME - Static Recompilation
#
# Copy this template to your game project root and customize:
#   1. Change the project name below
#   2. Set XBOXRECOMP_DIR to where you cloned xboxrecomp
#   3. Adjust source file lists as you add game-specific code
#   4. Add any game-specific compile definitions or link libraries
# ============================================================================

project(your_game_recomp C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Common definitions
add_compile_definitions(
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

# ── xboxrecomp toolkit ──────────────────────────────────────────
#
# Option A: xboxrecomp as a subdirectory (simplest)
#   Place xboxrecomp/ next to your game project and use a relative path.
#
# Option B: find_package (if you install xboxrecomp system-wide)
#   find_package(xboxrecomp REQUIRED)
#
# Adjust this path to point to your xboxrecomp clone:
set(XBOXRECOMP_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../xboxrecomp" CACHE PATH
    "Path to the xboxrecomp toolkit root directory")

# Add xboxrecomp as a subdirectory -- this builds all 6 runtime libraries
# and provides the 'xboxrecomp' umbrella target to link against.
add_subdirectory(${XBOXRECOMP_DIR} ${CMAKE_BINARY_DIR}/xboxrecomp)

# ── Exact target identity ───────────────────────────────────────
#
# The build regenerates a C header only after the standalone profile, parser
# analysis, and exact XBE agree. This prevents stale reference-title addresses
# from entering the runtime executable.
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(TARGET_PROFILE "${CMAKE_CURRENT_SOURCE_DIR}/target-profile.json" CACHE FILEPATH
    "Validated per-title target profile")
set(TARGET_ANALYSIS_JSON "${CMAKE_CURRENT_SOURCE_DIR}/analysis/target_analysis.json" CACHE FILEPATH
    "Machine-readable output from tools.xbe_parser for the exact XBE")
set(TARGET_XBE "${CMAKE_CURRENT_SOURCE_DIR}/game/default.xbe" CACHE FILEPATH
    "Exact target XBE used for profile hash and section-bound validation")
set(TARGET_PROFILE_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated/target_profile.h")

add_custom_command(
    OUTPUT ${TARGET_PROFILE_HEADER}
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/generated"
    COMMAND ${Python3_EXECUTABLE} -m tools.target_profile emit-c-header
            --profile "${TARGET_PROFILE}"
            --analysis-json "${TARGET_ANALYSIS_JSON}"
            --xbe "${TARGET_XBE}"
            --output "${TARGET_PROFILE_HEADER}"
    DEPENDS ${TARGET_PROFILE} ${TARGET_ANALYSIS_JSON} ${TARGET_XBE}
            ${XBOXRECOMP_DIR}/tools/target_profile.py
    WORKING_DIRECTORY ${XBOXRECOMP_DIR}
    VERBATIM
)
add_custom_target(generate_target_profile_header DEPENDS ${TARGET_PROFILE_HEADER})

# ── Recompiled game executable ──────────────────────────────────

# Collect generated recompiled code.
# The recomp pipeline outputs files into src/recomp/gen/.
# With --split 1000, you get gen_0000.c, gen_0001.c, etc.
file(GLOB RECOMP_GEN_SOURCES "src/recomp/gen/*.c")

# Core game sources
set(GAME_SOURCES
    src/main.c
    src/recomp_manual.c
    # Add game-specific sources here, e.g.:
    # src/asset_loader.c
    # src/custom_renderer.c
)

# The recomp pipeline also generates a dispatch header and function declarations.
# These are included by the generated .c files:
#   src/recomp/gen/recomp_funcs.h    - extern declarations for all recompiled functions
#   src/recomp/recomp_dispatch.h     - binary search dispatch table
#   src/recomp/recomp_types.h        - register model, ICALL macros, MEM helpers

add_executable(${PROJECT_NAME} WIN32
    ${GAME_SOURCES}
    ${RECOMP_GEN_SOURCES}
    ${TARGET_PROFILE_HEADER}
)
add_dependencies(${PROJECT_NAME} generate_target_profile_header)

# Link against the xboxrecomp umbrella target (all 6 runtime libraries)
target_link_libraries(${PROJECT_NAME} PRIVATE xboxrecomp)

# Include paths for generated recomp headers
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/recomp
    ${CMAKE_CURRENT_BINARY_DIR}/generated
    ${XBOXRECOMP_DIR}/include
)

# Windows SDK libraries needed at link time
target_link_libraries(${PROJECT_NAME} PRIVATE
    d3d11
    dxgi
    dxguid
    xinput
    winmm
)

# MSVC-specific: large address aware, increase section limit for big generated files
if(MSVC)
    target_link_options(${PROJECT_NAME} PRIVATE
        /LARGEADDRESSAWARE
    )
    # The generated code files can be very large. Increase object file section limit.
    target_compile_options(${PROJECT_NAME} PRIVATE /bigobj)
endif()

# ── Game-specific additions ─────────────────────────────────────
#
# Add any game-specific libraries, loaders, or custom renderers below.
# Examples:
#
# # Custom texture loader for your game's format
# target_sources(${PROJECT_NAME} PRIVATE src/texture_loader.c)
#
# # If your game uses RenderWare, you may need a RW bridge layer
# target_sources(${PROJECT_NAME} PRIVATE src/rw_bridge.c)
#
# # Additional compile definitions for debugging
# target_compile_definitions(${PROJECT_NAME} PRIVATE
#     ENABLE_ICALL_TRACE=1
#     VERBOSE_KERNEL_LOG=1
# )
