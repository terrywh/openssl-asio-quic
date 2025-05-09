#ifndef QUIC_CONNECT_H
#define QUIC_CONNECT_H

#include "endpoint_resolve_result.hpp"
#include "connection.hpp"
#include "impl/connection_connect.hpp"

namespace quic {

template <class CompletionToken>
auto async_connect(connection& conn, const endpoint_resolve_result& eps, CompletionToken&& token) {
    return boost::asio::async_compose<CompletionToken, void (boost::system::error_code)>(
        impl::connection_connect_async_seq{conn.impl_, eps}, token);
}

auto connect(connection& conn, const endpoint_resolve_result& eps) {
    return impl::connection_connect_seq{conn.impl_, eps}();
}

} // namespace quic

#endif // QUIC_CONNECT_H
