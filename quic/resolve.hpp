#ifndef QUIC_RESOLVE_H
#define QUIC_RESOLVE_H

#include "proto.hpp"
#include "basic_endpoint.hpp"

namespace quic {

template <class Protocol = proto>
basic_endpoints<Protocol> resolve(const std::string& hostname, const std::string& service) {
    BIO_ADDRINFO* addr;

    Protocol proto = Protocol::unspecified();
    if (int r = BIO_lookup_ex(hostname.c_str(), service.c_str(), BIO_LOOKUP_CLIENT,
        proto.family(), proto.type(), proto.protocol(), &addr); r == 0) {
        
        throw boost::system::system_error(SSL_get_error(nullptr, r), boost::asio::error::get_ssl_category());
    }
    
    return basic_endpoints<Protocol>{addr};
}



} // namespace quic

#endif // QUIC_RESOLVE_H
