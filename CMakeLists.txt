cmake_minimum_required(VERSION 2.8)

# common
project(sepolicy-inject)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wshadow -Werror -fno-strict-aliasing -Os")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static")

include_directories(
    include
)

# libsepolicy_inject
add_library(sepolicy_inject
    src/sepolicy-inject-6.c
    src/sepolicy-inject-7.c
    src/sepolicy-inject-public-interface.c
    src/tokenize.c
)

# sepolicy-inject
add_executable(sepolicy-inject
    src/main.c
)
target_link_libraries(sepolicy-inject sepolicy_inject sepol6 sepol7)
