#ifndef QUIC_RESOLVE_H
#define QUIC_RESOLVE_H

#include "proto.hpp"
#include "endpoint.hpp"

namespace quic {

endpoint_resolve_result resolve(const std::string& hostname, const std::string& service) {
    BIO_ADDRINFO* addr;

    auto p = proto::unspecified();
    if (int r = BIO_lookup_ex(hostname.c_str(), service.c_str(), BIO_LOOKUP_CLIENT,
        p.family(), p.type(), p.protocol(), &addr); r == 0) {

        throw boost::system::system_error {
            static_cast<int>(ERR_get_error()),
            boost::asio::error::get_ssl_category()};
    }

    return endpoint_resolve_result{addr};
}

// TODO async_resolve ?

} // namespace quic

#endif // QUIC_RESOLVE_H
