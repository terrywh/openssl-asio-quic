set_project("quic")
set_languages("c17", "cxx20")

vendor = {}
vendor["boost"] = "/data/vendor/boost"
vendor["openssl"] = "/data/vendor/openssl"

add_sysincludedirs(
    vendor["boost"] .. "/include",
    vendor["openssl"] .. "/include")
add_linkdirs(
    vendor["boost"] .. "/lib",
    vendor["openssl"] .. "/lib")
add_links(
    "boost_system", "ssl", "crypto")

target("quic")
    set_kind("headeronly")
    add_headerfiles(
        "quic.hpp",
        "quic/**.hpp",
        "quic/**.ipp")
    
target("quic-bsync")
    set_kind("binary")
    add_deps("quic")
    add_rules("mode.debug", "mode.release")
    add_files("test/bsync.cpp")

target("quic-async")
    set_kind("binary")
    add_deps("quic")
    add_rules("mode.debug", "mode.release")
    add_files("test/async.cpp")

target("quic-test")
    set_kind("binary")
    add_deps("quic")
    add_rules("mode.debug", "mode.release")
    add_files("test/test.cpp")
