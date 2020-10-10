add_executable(opendht-test main.cpp)
target_include_directories(opendht-test PRIVATE ${opendht_SOURCE_DIR}/include ${cxxopts_SOURCE_DIR}/include)  
target_link_libraries(opendht-test opendht-static fmt::fmt)