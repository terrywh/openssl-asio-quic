#ifndef QUIC_DETAIL_READ_SOME_H
#define QUIC_DETAIL_READ_SOME_H

#include "connection_base.hpp"
#include "stream_base.hpp"

namespace quic {
namespace detail {

template <class Protocol, class Executor, class MutableBufferSequence>
struct do_read_some {
    using connection_type = connection_base<Protocol, Executor>;
    using stream_type = stream_base<Protocol, Executor>;
    using mutable_buffers_type = typename std::decay<MutableBufferSequence>::type;

    connection_type* conn_;
    stream_type* stream_;
    const mutable_buffers_type& buffers_;

    do_read_some(connection_type* conn, stream_type* stream, const mutable_buffers_type& buffers)
    : conn_(conn)
    , stream_(stream)
    , buffers_(buffers) {}

    std::size_t operator()() {
        std::size_t read = 0;
        for (auto i=boost::asio::buffer_sequence_begin(buffers_); i!=boost::asio::buffer_sequence_end(buffers_); ++i) {
            boost::asio::mutable_buffer buffer = *i;
            std::size_t size;
            if (int r = SSL_read_ex(stream_->handle_, buffer.data(), buffer.size(), &size); r <= 0) {
                int err = SSL_get_error(conn_->handle_, r);
                switch (err) {
                case SSL_ERROR_SYSCALL:
                    throw boost::system::system_error{errno, boost::asio::error::get_system_category()};
                default:
                    throw boost::system::system_error{err, boost::asio::error::get_ssl_category()};
                }
            }
            read += size;
            if (size != buffer.size()) {
                break;
            }
        }
        return read;
    }
};

template <class Protocol, class Executor, class MutableBufferSequence>
struct do_async_read_some {
    using connection_type = connection_base<Protocol, Executor>;
    using stream_type = stream_base<Protocol, Executor>;
    using mutable_buffers_type = typename std::decay<MutableBufferSequence>::type;

    connection_type* conn_;
    stream_type* stream_;
    const mutable_buffers_type& buffers_;
    int start_;
    std::size_t read_;
    enum {preparing, reading} state_;
    boost::asio::mutable_buffer buffer_;

    do_async_read_some(connection_type* conn, stream_type* stream, const mutable_buffers_type& buffers)
    : conn_(conn)
    , stream_(stream)
    , buffers_(buffers)
    , start_(0)
    , read_(0)
    , state_(preparing) {}

    boost::asio::mutable_buffer next_buffer() {
        auto i = boost::asio::buffer_sequence_begin(buffers_);
        std::advance(i, start_++);
        if (i == boost::asio::buffer_sequence_end(buffers_)) 
            return {};
        return *i;
    }

    template <typename Self>
    void operator()(Self& self, boost::system::error_code error = {}, std::size_t size = 0) {
        if (error) {
            self.complete(error, read_);
            return;
        }
READ_NEXT:
        switch (state_) {
        case preparing:
            state_ = reading;
            buffer_ = next_buffer();
            [[fallthrough]];
        case reading:
            if (buffer_.size() == 0) {
                self.complete(error, read_);
                return;
            }
            if (int r = SSL_read_ex(stream_->handle_, buffer_.data(), buffer_.size(), &size); r <= 0) {
                int err = SSL_get_error(stream_->handle_, r);
                switch(err) {
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
                    conn_->async_wait(std::move(self));
                    break;
                case SSL_ERROR_SYSCALL:
                    self.complete(boost::system::error_code{errno, boost::asio::error::get_system_category()}, read_);
                    break;
                case SSL_ERROR_ZERO_RETURN:
                    self.complete(boost::system::error_code{SSL_R_STREAM_FINISHED, boost::asio::error::get_ssl_category()}, read_);
                    break;
                default:
                    self.complete(boost::system::error_code{err, boost::asio::error::get_ssl_category()}, read_);
                }
                return;
            } else if (size != buffer_.size()) {
                read_ += size;
                self.complete(error, read_);
                return;
            } else {
                state_ = preparing;
                read_ += size;
                goto READ_NEXT;
            }
        }
    }
};


} // namespace detail
} // namespace quic

#endif // QUIC_DETAIL_READ_SOME_H
