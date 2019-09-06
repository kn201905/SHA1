# set(CMAKE_VERBOSE_MAKEFILE 1)
cmake_minimum_required(VERSION 3.0)

# set(Boost_USE_STATIC_LIBS ON)
# set(Boost_USE_MULTITHREADED ON)
# project(chatsvr)

# set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -std=c++17 -Wall")
set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -std=c++17)

# set(MY_BOOST_DIR /home/boost/1_71_0)
# set(MY_BOOST_LIB_DIR ${MY_BOOST_DIR}/lib)
# include_directories(${MY_BOOST_DIR}/include)

# link_directories(dir)

# set(MY_MAIN_DIR /shared/cpp/chatsvr)

# add_subdirectory(dir_sub)
# dir_sub 内では  add_library(foo STATIC sub1.cpp sub2.cpp) のようにする

set(MY_SOURCES main.cpp SHA1.o)
add_executable(sha1 ${MY_SOURCES})

# target_link_libraries(
#	sha1
#	${MY_CRYPTO_DIR}/libcryptopp.a
#	${MY_BOOST_LIB_DIR}/libboost_iostreams.a
#	${MY_MAIN_DIR}/KgLog/build/lib_KgLog.a
# )
