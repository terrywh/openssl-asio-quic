#ifndef QUIC_IMPL_STREAM_WRITE_SOME_H
#define QUIC_IMPL_STREAM_WRITE_SOME_H

#include "../detail/error_handler.hpp"
#include "connection.hpp"
#include "stream.hpp"

namespace quic {
namespace impl {

template <class ConstBufferSequence>
struct stream_write_some {
    using const_buffers_type = typename std::decay<ConstBufferSequence>::type;

    impl::connection* conn_;
    impl::stream* stream_;
    const const_buffers_type& buffers_;

    stream_write_some(impl::connection* conn, impl::stream* stream, const const_buffers_type& buffers)
    : conn_(conn)
    , stream_(stream)
    , buffers_(buffers) {}

    std::size_t operator()() {
        std::size_t total = 0, write;
        for (auto i=boost::asio::buffer_sequence_begin(buffers_); i!=boost::asio::buffer_sequence_end(buffers_); ++i) {
            boost::asio::const_buffer buffer = *i;
            if (int r = SSL_write_ex(stream_->handle_, buffer.data(), buffer.size(), &write); r <= 0) {
                detail::error_handler(SSL_get_error(conn_->handle_, r)).throws();
            } else {
                total += write; // 默认情况 SSL_MODE_ENABLE_PARTIAL_WRITE 未启用，未发生错误时一定完成了写入
            }
        }
        return total;
    }
};


template <class ConstBufferSequence>
struct stream_write_some_async {
    using const_buffers_type = typename std::decay<ConstBufferSequence>::type;

    impl::connection* conn_;
    impl::stream* stream_;
    const const_buffers_type& buffers_;
    std::size_t wrote_;
    std::size_t start_;
    enum {preparing, writing} state_;
    boost::asio::const_buffer buffer_;

    stream_write_some_async(impl::connection* conn, impl::stream* stream, const const_buffers_type& buffers)
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
                if (detail::error_handler(SSL_get_error(conn_->handle_, r)).wait_ex(self, wrote_))
                    conn_->async_wait(std::move(self));
            } else {
                state_ = preparing; // 下一个待写入的区块
                wrote_ += size;
                goto WRITE_NEXT;
            }
        }
    }
};

} // namespace impl
} // namespace quic

#endif // QUIC_IMPL_STREAM_WRITE_SOME_H
