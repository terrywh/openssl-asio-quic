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

target("block_client")
    set_kind("binary")
    add_deps("quic")
    add_rules("mode.debug", "mode.release")
    add_files("test/block_client.cpp")

target("async_client")
    set_kind("binary")
    add_deps("quic")
    add_rules("mode.debug", "mode.release")
    add_files("test/async_client.cpp")

target("block_server")
    set_kind("binary")
    add_deps("quic")
    add_rules("mode.debug", "mode.release")
    add_files("test/block_server.cpp")

target("async_server")
    set_kind("binary")
    add_deps("quic")
    add_rules("mode.debug", "mode.release")
    add_files("test/async_server.cpp")

target("test")
    set_kind("binary")
    add_rules("mode.debug", "mode.release")
    add_files("test/test.cpp")
