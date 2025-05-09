#ifndef QUIC_IMPL_CONNECTION_CREATE_STREAM_H
#define QUIC_IMPL_CONNECTION_CREATE_STREAM_H

#include "connection.hpp"
#include "stream.hpp"

namespace quic {
namespace impl {

struct connection_create_stream {
    impl::connection* conn_;
    impl::stream*   stream_;

    connection_create_stream(impl::connection* conn, impl::stream* stream)
    : conn_(conn)
    , stream_(stream) { }

    void operator()() const {
        if (stream_->handle_ = SSL_new_stream(conn_->handle_, SSL_STREAM_FLAG_NO_BLOCK); stream_->handle_ == nullptr) {
            int err = SSL_get_error(this->conn_->handle_, 0);
            switch (err) {
            case SSL_ERROR_SYSCALL:
                throw boost::system::system_error{errno, boost::asio::error::get_system_category()};
                break;
            default:
                throw boost::system::system_error{err, boost::asio::error::get_ssl_category()};
            }
        }
    }
};

struct connection_create_stream_async {
    impl::connection* conn_;
    impl::stream*   stream_;

    connection_create_stream_async(impl::connection* conn, impl::stream* stream)
    : conn_(conn)
    , stream_(stream) { }

    template <typename Self>
    void operator()(Self& self, boost::system::error_code error = {}) {
        if (error) {
            self.complete(error);
            return;
        }
        if (stream_->handle_ = SSL_new_stream(conn_->handle_, SSL_STREAM_FLAG_NO_BLOCK); stream_->handle_ == nullptr) {
            int err = SSL_get_error(this->conn_->handle_, 0);
            switch (err) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                this->conn_->async_wait(std::move(self));
                break;
            case SSL_ERROR_SYSCALL:
                self.complete(boost::system::error_code{errno, boost::asio::error::get_system_category()});
                break;
            default:
                self.complete(boost::system::error_code{err, boost::asio::error::get_ssl_category()});
            }
            return;
        }
        self.complete(error);
    }
};


} // namespace impl
} // namespace quic

#endif // QUIC_IMPL_CONNECTION_CREATE_STREAM_H
