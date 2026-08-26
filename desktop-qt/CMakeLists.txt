cmake_minimum_required(VERSION 3.24)
project(midorivpn_desktop_qt VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
# The RPM loader only uses distribution Qt libraries. Do not emit an empty
# RUNPATH, which Fedora correctly rejects as a packaging/security error.
set(CMAKE_SKIP_RPATH TRUE)

find_package(Qt6 6.8 REQUIRED COMPONENTS Core Gui Widgets Network)

qt_standard_project_setup()
qt_add_executable(midorivpn-desktop-ui main.cpp)
target_link_libraries(midorivpn-desktop-ui PRIVATE
  Qt6::Core
  Qt6::Gui
  Qt6::Widgets
  Qt6::Network
)

install(TARGETS midorivpn-desktop-ui RUNTIME DESTINATION libexec)
