# The following five lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)
set(EXTRA_COMPONENT_DIRS /home/alejandro/puf_copy/esp32_puflib)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(project_utilities)
