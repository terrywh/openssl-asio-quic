#ifndef QUIC_IMPL_STREAM_READ_SOME_H
#define QUIC_IMPL_STREAM_READ_SOME_H

#include "../detail/error_handler.hpp"
#include "connection.hpp"
#include "stream.hpp"

namespace quic {
namespace impl {

template <class MutableBufferSequence>
struct stream_read_some {
    impl::connection* conn_;
    impl::stream*   stream_;
    const MutableBufferSequence& buffers_;

    stream_read_some(impl::connection* conn, impl::stream* stream, const MutableBufferSequence& buffers)
    : conn_(conn)
    , stream_(stream)
    , buffers_(buffers) {}

    std::size_t operator()() {
        std::size_t read = 0;
        for (auto i=boost::asio::buffer_sequence_begin(buffers_); i!=boost::asio::buffer_sequence_end(buffers_); ++i) {
            boost::asio::mutable_buffer buffer = *i;
            std::size_t size;
            if (int r = SSL_read_ex(stream_->handle_, buffer.data(), buffer.size(), &size); r <= 0) {
                detail::error_handler(SSL_get_error(conn_->handle_, r)).throws();
            }
            read += size;
            if (size != buffer.size()) {
                break;
            }
        }
        return read;
    }
};

template <class MutableBufferSequence>
struct stream_read_some_async {
    impl::connection* conn_;
    impl::stream*   stream_;
    const MutableBufferSequence& buffers_;
    int start_;
    std::size_t read_;
    enum {preparing, reading} state_;
    boost::asio::mutable_buffer buffer_;

    stream_read_some_async(impl::connection* conn, impl::stream* stream, const MutableBufferSequence& buffers)
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
                if (detail::error_handler(SSL_get_error(stream_->handle_, r)).wait_ex(self, read_))
                    conn_->async_wait(std::move(self));
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


} // namespace impl
} // namespace quic

#endif // QUIC_IMPL_STREAM_READ_SOME_H
