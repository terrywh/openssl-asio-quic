#ifndef BOOST_ASIO_QUIC_BASIC_SERVER_H
#define BOOST_ASIO_QUIC_BASIC_SERVER_H

#include "detail/connection_base.hpp"
#include "detail/stream_base.hpp"
#include "detail/read_some.hpp"
#include "detail/write_some.hpp"

namespace quic {

template <class Protocol, class Executor = boost::asio::any_io_executor>
class basic_stream: public detail::stream_base<Protocol, Executor> {
    template <class Protocol1, class Executor1>
    friend class basic_connection;

public:
    using protocol_type = typename std::decay<Protocol>::type;
    using executor_type = typename std::decay<Executor>::type;


private:
    basic_stream(detail::connection_base<Protocol, Executor>& conn, SSL* stream)
    : detail::stream_base<Protocol, Executor>(conn, stream) {}

public:

    template <class MutableBufferSequence>
    std::size_t read_some(const MutableBufferSequence& buffers) {
        std::size_t read = 0;
        for (auto i=boost::asio::buffer_sequence_begin(buffers); i!=boost::asio::buffer_sequence_end(buffers); ++i) {
            boost::asio::mutable_buffer buffer = *i;
            std::size_t size;
            if (int r = SSL_read_ex(this->ssl_, buffer.data(), buffer.size(), &size); r <= 0) {
                throw boost::system::system_error(SSL_get_error(this->ssl_, r), boost::asio::error::get_ssl_category());
            }
            read += size;
            if (size != buffer.size()) {
                break;
            }
        }
        return read;
    }

    template <class MutableBufferSequence, class CompletionToken>
    auto async_read_some(const MutableBufferSequence& buffers, CompletionToken&& token) -> decltype(
        boost::asio::async_compose<
            CompletionToken,
            void (boost::system::error_code, std::size_t),
            detail::read_some_impl<Protocol, Executor, MutableBufferSequence>>(
            std::declval<detail::read_some_impl<Protocol, Executor, MutableBufferSequence>>(),
            token)) {
        
                // detail::read_some_impl<Protocol, Executor, MutableBufferSequence> x{this->conn_, *this, buffers, 0, 0}; 
        return  boost::asio::async_compose<
                CompletionToken,
                void (boost::system::error_code, std::size_t),
                detail::read_some_impl<Protocol, Executor, MutableBufferSequence>>(
            detail::read_some_impl<Protocol, Executor, MutableBufferSequence>{this->conn_, *this, buffers, 0, 0},
            token);
    }

    template <class ConstBufferSequence>
    std::size_t write_some(const ConstBufferSequence& buffers) {
        std::size_t write = 0;
        for (auto i=boost::asio::buffer_sequence_begin(buffers); i!=boost::asio::buffer_sequence_end(buffers); ++i) {
            boost::asio::const_buffer buffer = *i;
            std::size_t size;
            if (int r = SSL_write_ex(this->ssl_, buffer.data(), buffer.size(), &size); r <= 0) {
                throw boost::system::system_error(SSL_get_error(this->ssl_, r), boost::asio::error::get_ssl_category());
            }
            write += size;
            // 默认情况 SSL_MODE_ENABLE_PARTIAL_WRITE 未启用，未发生错误时一定完成了写入
        }
        return write;
    }

    template <class ConstBufferSequence, class CompletionToken>
    auto async_write_some(const ConstBufferSequence& buffers, CompletionToken&& token) -> decltype(
        boost::asio::async_compose<detail::write_some_impl<Protocol, Executor, ConstBufferSequence>,
                void (boost::system::error_code, std::size_t)>(
            std::declval<detail::write_some_impl<Protocol, Executor, ConstBufferSequence>>(),
            token)) {
        return  boost::asio::async_compose<detail::write_some_impl<Protocol, Executor, ConstBufferSequence>,
                void (boost::system::error_code, std::size_t)>(
            detail::write_some_impl<Protocol, Executor, ConstBufferSequence>{this->conn_, *this, buffers},
            token
        );
    }

    void shutdown(boost::asio::socket_base::shutdown_type what) {
        switch (what) {
        case boost::asio::socket_base::shutdown_both:
            [[fallthrough]];
        case boost::asio::socket_base::shutdown_send:
            if (int r = SSL_stream_conclude(this->ssl_, 0); r != 1) {
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
