include(FetchContent)

set(OPENDHT_SHARED OFF CACHE INTERNAL "")
set(OPENDHT_TOOLS OFF CACHE INTERNAL "")

FetchContent_Declare(
    opendht
    GIT_REPOSITORY  https://github.com/savoirfairelinux/opendht.git
    GIT_TAG         2.1.6
)
FetchContent_Declare(
    fmt
    GIT_REPOSITORY  https://github.com/fmtlib/fmt.git
    GIT_TAG         7.0.3
)

set(CXXOPTS_BUILD_EXAMPLES OFF CACHE INTERNAL "")
set(CXXOPTS_BUILD_TESTS OFF CACHE INTERNAL "")
set(CXXOPTS_ENABLE_INSTALL OFF CACHE INTERNAL "")

FetchContent_Declare(
    cxxopts
    GIT_REPOSITORY  https://github.com/jarro2783/cxxopts.git
    GIT_TAG         v2.2.1
)

FetchContent_MakeAvailable(opendht)
FetchContent_MakeAvailable(fmt)
FetchContent_MakeAvailable(cxxopts)