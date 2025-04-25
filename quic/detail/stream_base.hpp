#ifndef QUIC_DETAIL_STREAM_BASE_H
#define QUIC_DETAIL_STREAM_BASE_H

#include "connection_base.hpp"
#include <iostream>

namespace quic {
namespace detail {

template <class Protocol, class Executor>
struct stream_base {

    using protocol_type = typename std::decay<Protocol>::type;
    using connection_type = connection_base<Protocol, Executor>;
    using executor_type = connection_type::executor_type;
    using socket_type = boost::asio::basic_datagram_socket<Protocol, Executor>;

    SSL* handle_ = nullptr;
    
    ~stream_base() {
        SSL_free(handle_);
    }
};

} // namespace detail
} // namespace quic

#endif // QUIC_DETAIL_STREAM_BASE_H
