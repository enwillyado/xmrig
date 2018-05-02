set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 11)

if ("${CMAKE_BUILD_TYPE}" STREQUAL "")
    set(CMAKE_BUILD_TYPE Release)
endif()

 if (CMAKE_BUILD_TYPE STREQUAL "Release")
     add_definitions(/DNDEBUG)
 endif()
 
if (CMAKE_CXX_COMPILER_ID MATCHES GNU)

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wno-strict-aliasing -DFOUR_WAY -msse -msse2 -msse3 -mmmx -m3dnow")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Ofast -ffast-math -s -funroll-loops -fvariable-expansion-in-unroller -fmerge-all-constants -fbranch-target-load-optimize2")

    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-strict-aliasing -DFOUR_WAY -msse -msse2 -msse3 -mmmx -m3dnow")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Ofast -ffast-math -s -funroll-loops -fpermissive -fvariable-expansion-in-unroller -fmerge-all-constants -fbranch-target-load-optimize2")

    if (XMRIG_ARMv8)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv8-a+crypto")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=armv8-a+crypto -flax-vector-conversions")
    elseif (XMRIG_ARMv7)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfpu=neon")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfpu=neon -flax-vector-conversions")
    else()
	if (XMRIG_ARCH)
	        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=${XMRIG_ARCH} -mtune=${XMRIG_ARCH} -maes")
        	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=${XMRIG_ARCH} -mtune=${XMRIG_ARCH} -maes")
	else()
	        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -maes")
        	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes")
	    endif()
    endif()

    if (WIN32)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -flto")
    else()
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -flto")
    endif()

    add_definitions(/D_GNU_SOURCE)

    if (${CMAKE_VERSION} VERSION_LESS "3.1.0")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
    endif()

    if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -ggdb")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -ggdb")
    endif()

elseif (CMAKE_CXX_COMPILER_ID MATCHES MSVC)

    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /Ox /Ot /Oi /MT /GL")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /Ox /Ot /Oi /MT /GL")
    add_definitions(/D_CRT_SECURE_NO_WARNINGS)
    add_definitions(/D_CRT_NONSTDC_NO_WARNINGS)
    add_definitions(/DNOMINMAX)

elseif (CMAKE_CXX_COMPILER_ID MATCHES Clang)

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fmerge-all-constants")

    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Ofast -fno-exceptions -Wno-missing-braces")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Ofast -fmerge-all-constants")

    if (XMRIG_ARMv8)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv8-a+crypto")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=armv8-a+crypto")
    elseif (XMRIG_ARMv7)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfpu=neon -march=${CMAKE_SYSTEM_PROCESSOR}")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfpu=neon -march=${CMAKE_SYSTEM_PROCESSOR}")
    else()
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -maes")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes")
    endif()

endif()
