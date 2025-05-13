#ifndef BOOST_ASIO_QUIC_BASIC_SERVER_H
#define BOOST_ASIO_QUIC_BASIC_SERVER_H

#include "detail/ssl.hpp"
#include "impl/connection.hpp"
#include "impl/stream.hpp"
#include "impl/stream_read_some.hpp"
#include "impl/stream_write_some.hpp"
#include <utility> // std::exchange | std::swap

namespace quic {

class connection;

class stream {
    friend class connection;

    impl::connection* conn_ = nullptr;
    impl::stream*     impl_ = nullptr;

public:
    using executor_type = impl::connection::executor_type;
    stream() = default;
    stream(impl::connection* conn)
    : conn_(conn)
    , impl_(detail::ssl_extra_data::emplace<impl::stream>(nullptr, conn_)) {
        SSL_up_ref(conn_->handle_);
    }
    stream(const stream&& s) = delete;
    stream(stream&& s) noexcept
    : conn_(std::exchange(s.conn_, nullptr))
    , impl_(std::exchange(s.impl_, nullptr)) {}
    ~stream() {
        if (conn_ != nullptr) SSL_free(conn_->handle_);
        if (impl_ != nullptr) SSL_free(impl_->handle_);
    }

    stream& operator =(const stream& s) = delete;
    stream& operator =(stream&& s) noexcept {
        std::swap(conn_, s.conn_);
        std::swap(impl_, s.impl_);
        return *this;
    }

    executor_type& get_executor() const {
        return impl_->strand_;
    }
    
    template <class MutableBufferSequence>
    std::size_t read_some(const MutableBufferSequence& buffers) {
       return impl::stream_read_some{conn_, impl_, buffers}();
    }
    template <class MutableBufferSequence, class CompletionToken>
    auto async_read_some(const MutableBufferSequence& buffers, CompletionToken&& token) {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)>(
            impl::stream_read_some_async<MutableBufferSequence>{conn_, impl_, buffers}, token);
    }
    template <class ConstBufferSequence>
    std::size_t write_some(const ConstBufferSequence& buffers) {
        return impl::stream_write_some<ConstBufferSequence>{conn_, impl_, buffers}();
    }
    template <class ConstBufferSequence, class CompletionToken>
    auto async_write_some(const ConstBufferSequence& buffers, CompletionToken&& token) {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)>(
            impl::stream_write_some_async<ConstBufferSequence>{conn_, impl_, buffers}, token);
    }

    void shutdown(boost::asio::socket_base::shutdown_type what) {
        switch (what) {
        case boost::asio::socket_base::shutdown_both:
            [[fallthrough]];
        case boost::asio::socket_base::shutdown_send:
            if (int r = SSL_stream_conclude(impl_->handle_, 0); r != 1) {
                throw std::runtime_error("failed to shutdown stream (send)");
            }
            break;
        case boost::asio::socket_base::shutdown_receive:
            // TODO
            break;
        }
    }

};

} // namespace quic

#endif // ASIO_QUIC_BASIC_SERVER_H
