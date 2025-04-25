#ifndef QUIC_DETAIL_WRITE_SOME_H
#define QUIC_DETAIL_WRITE_SOME_H

#include "connection_base.hpp"
#include "stream_base.hpp"

namespace quic {
namespace detail {

template <class Protocol, class Executor, class ConstBufferSequence>
struct do_write_some {
    using connection_type = connection_base<Protocol, Executor>;
    using stream_type = stream_base<Protocol, Executor>;
    using const_buffers_type = typename std::decay<ConstBufferSequence>::type;

    connection_type* conn_;
    stream_type* stream_;
    const const_buffers_type& buffers_;

    do_write_some(connection_type* conn, stream_type* stream, const const_buffers_type& buffers)
    : conn_(conn)
    , stream_(stream)
    , buffers_(buffers) {}

    std::size_t operator()() {
        std::size_t total = 0, write;
        for (auto i=boost::asio::buffer_sequence_begin(buffers_); i!=boost::asio::buffer_sequence_end(buffers_); ++i) {
            boost::asio::const_buffer buffer = *i;
            if (int r = SSL_write_ex(stream_->handle_, buffer.data(), buffer.size(), &write); r <= 0) {
                int err = SSL_get_error(conn_->handle_, r);
                switch (err) {
                case SSL_ERROR_SYSCALL:
                    throw boost::system::system_error{errno, boost::asio::error::get_system_category()};
                default:
                    throw boost::system::system_error{err, boost::asio::error::get_ssl_category()};
                }
            } else {
                total += write; // 默认情况 SSL_MODE_ENABLE_PARTIAL_WRITE 未启用，未发生错误时一定完成了写入
            }
        }
        return total;
    }
};


template <class Protocol, class Executor, class ConstBufferSequence>
struct do_async_write_some {
    using connection_type = connection_base<Protocol, Executor>;
    using stream_type = stream_base<Protocol, Executor>;
    using const_buffers_type = typename std::decay<ConstBufferSequence>::type;

    connection_type* conn_;
    stream_type* stream_;
    const const_buffers_type& buffers_;
    std::size_t wrote_;
    std::size_t start_;
    enum {preparing, writing} state_;
    boost::asio::const_buffer buffer_;

    do_async_write_some(connection_type* conn, stream_type* stream, const const_buffers_type& buffers)
    : conn_(conn)
    , stream_(stream)
    , buffers_(buffers)
    , wrote_(0)
    , start_(0)
    , state_(preparing) {}

    boost::asio::const_buffer next_buffer() {
        auto i = boost::asio::buffer_sequence_begin(buffers_);
        std::advance(i, start_++);
        if (i == boost::asio::buffer_sequence_end(buffers_)) 
            return {};
        return *i;
    }

    template <class Self>
    void operator()(Self& self, boost::system::error_code error = {}, std::size_t size = 0) {
        if (error) {
            self.complete(error, wrote_);
            return;
        }
WRITE_NEXT:
        switch (state_) {
        case preparing:
            state_ = writing;
            buffer_ = next_buffer();
            [[fallthrough]];
        case writing:
            if (buffer_.size() == 0) {
                self.complete(error, wrote_);
                return;
            }
            if (int r = SSL_write_ex(stream_->handle_, buffer_.data(), buffer_.size(), &size); r <= 0) {
                int err = SSL_get_error(this->conn_->handle_, r);
                switch (err) {
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
                    conn_->async_wait(std::move(self));
                    break;
                case SSL_ERROR_SYSCALL:
                    self.complete(boost::system::error_code{errno, boost::asio::error::get_system_category()}, wrote_);
                    break;
                default:
                    self.complete(boost::system::error_code{err, boost::asio::error::get_ssl_category()}, wrote_);
                }
            } else {
                state_ = preparing; // 下一个待写入的区块
                wrote_ += size;
                goto WRITE_NEXT;
            }
        }
    }
};

} // namespace detail
} // namespace quic

#endif // QUIC_DETAIL_WRITE_SOME_H
