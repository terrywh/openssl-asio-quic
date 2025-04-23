#ifndef QUIC_DETAIL_STREAM_BASE_H
#define QUIC_DETAIL_STREAM_BASE_H

#include "connection_base.hpp"

namespace quic {
namespace detail {

template <class Protocol, class Executor>
struct stream_base {

    using protocol_type = typename std::decay<Protocol>::type;
    using executor_type = typename std::decay<Executor>::type;
    using connection_type = connection_base<Protocol, Executor>;
    using socket_type = boost::asio::basic_datagram_socket<Protocol, Executor>;

    connection_base<Protocol, Executor>* conn_;
    SSL* handle_;

    stream_base(connection_base<Protocol, Executor>* conn)
    : conn_(conn)
    , handle_(nullptr) {
        conn_->add_ref();
    }

    ~stream_base() {
        SSL_free(handle_);
        conn_->del_ref();
    }

    void add_ref() {
        SSL_up_ref(handle_);
    }

    void del_ref() {
        SSL_free(handle_);
    }
};

} // namespace detail
} // namespace quic

#endif // QUIC_DETAIL_STREAM_BASE_H
