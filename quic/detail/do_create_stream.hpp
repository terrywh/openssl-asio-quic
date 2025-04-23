#ifndef QUIC_DETAIL_CREATE_STREAM_H
#define QUIC_DETAIL_CREATE_STREAM_H

#include "connection_base.hpp"
#include "stream_base.hpp"

namespace quic {
namespace detail {

template <class Protocol, class Executor>
struct do_create_stream {
    using connection_type = connection_base<Protocol, Executor>;
    using stream_type = stream_base<Protocol, Executor>;

    connection_type* conn_;
    stream_type*   stream_;

    do_create_stream(connection_type* conn, stream_type* stream)
    : conn_(conn)
    , stream_(stream) {

    }

    void operator()() const {
        stream_->handle_ = SSL_new_stream(conn_->handle_, SSL_STREAM_FLAG_NO_BLOCK);
        if (stream_->handle_ == nullptr) {
            throw boost::system::system_error(SSL_get_error(conn_->handle_, 0), boost::asio::error::get_ssl_category());
        }
        extra_data<stream_type>::attach(stream_->handle_, stream_);
    }
};
    

template <class Protocol, class Executor>
struct do_async_create_stream {
    using connection_type = connection_base<Protocol, Executor>;
    using stream_type = stream_base<Protocol, Executor>;

    connection_type* conn_;
    stream_type*   stream_;

    do_async_create_stream(connection_type* conn, stream_type* stream)
    : conn_(conn)
    , stream_(stream) {

    }

    template <typename Self>
    void operator()(Self& self, boost::system::error_code error = {}) {
        if (error) {
            self.complete(error);
            return;
        }
        if (stream_->handle_ = SSL_new_stream(conn_, SSL_STREAM_FLAG_NO_BLOCK); stream_->handle_ == nullptr) {
            conn_->handle_ssl_error(SSL_get_error(conn_, 0), std::move(self));
            return;
        }
        extra_data<stream_type>::attach(stream_->handle_, stream_);
        self.complete(error);
    }
};


} // namespace detail
} // namespace quic

#endif // QUIC_DETAIL_CREATE_STREAM_H
