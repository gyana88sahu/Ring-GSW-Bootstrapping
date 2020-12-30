cmake_minimum_required (VERSION 3.5.1)

project(bootstrap_gridstrap C CXX)
set(CMAKE_CXX_STANDARD 11)

if(APPLE)
        set(OPENMP_LIBRARIES "/usr/local/opt/libomp/lib")
        set(OPENMP_INCLUDES "/usr/local/opt/libomp/include")
endif()

OPTION (USE_OpenMP "Use OpenMP to enable <omp.h>" ON)

# Set OpenMP configuration manually for macOS
if(APPLE AND USE_OpenMP)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
       set(OpenMP_C_FLAGS "-Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument")
       set(OpenMP_C_LIB_NAMES "libomp")
       set(OpenMP_libomp_LIBRARY ${OpenMP_C_LIB_NAMES})
    endif()
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
       set(OpenMP_CXX_FLAGS "-Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument")
       set(OpenMP_CXX_LIB_NAMES "libomp")
       set(OpenMP_libomp_LIBRARY ${OpenMP_CXX_LIB_NAMES})
    endif()
endif()

find_package (OpenMP)

if( APPLE AND USE_OpenMP)
        include_directories("${OPENMP_INCLUDES}")
        link_directories("${OPENMP_LIBRARIES}")
        set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
        set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
endif()

# be sure to set PALISADE_DIR to the base install directory for PALISADE: -DPALISADE_DIR=/your/path

if( "${PALISADE_DIR}" STREQUAL "" )
	message(SEND_ERROR "PALISADE_DIR must be set to the install location for PALISADE")
endif()

include_directories( ${PALISADE_DIR}/palisade/include )
include_directories( ${PALISADE_DIR}/palisade/include/core )
include_directories( ${PALISADE_DIR}/palisade/include/pke )

link_directories( ${PALISADE_DIR}/palisade/lib )

link_libraries( PALISADEcore PALISADEpke )

### if using NTL include the next two lines, else don't
#link_libraries( gmp NTL )
#add_definitions(-DWITH_NTL)

### ADD YOUR EXECUTABLE(s) HERE
### add_executable( EXECUTABLE-NAME SOURCES )
###
### EXAMPLE: 
#add_subdirectory(src)

file (GLOB RGSW_DEPS CONFIGURE_DEPENDS src/*.cpp)
add_executable( demo-bootstrap demo/demo-bootstrap-rgsw.cpp ${RGSW_DEPS})
