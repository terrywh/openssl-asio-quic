#ifndef QUIC_CONNECT_H
#define QUIC_CONNECT_H

#include "basic_endpoint.hpp"
#include "basic_connection.hpp"
#include "detail/do_connect.hpp"

namespace quic {

template <class Protocol, class Executor, class CompletionToken>
auto async_connect(basic_connection<Protocol, Executor>& conn, const basic_endpoints<Protocol>& eps,
    CompletionToken&& token) {
    return boost::asio::async_compose<CompletionToken, void (boost::system::error_code)>(
        detail::do_async_connect_seq{conn, eps}, token);
}

template <class Protocol, class Executor>
auto connect(basic_connection<Protocol, Executor>& conn, const basic_endpoints<Protocol>& eps) {
    return detail::do_connect_seq{conn, eps}();
}

} // namespace quic

#endif // QUIC_CONNECT_H
