#ifndef BOOST_ASIO_QUIC_BASIC_SERVER_H
#define BOOST_ASIO_QUIC_BASIC_SERVER_H

#include "detail/stream_base.hpp"

namespace quic {

template <class Protocol, class Executor>
class basic_connection;

template <class Protocol, class Executor = boost::asio::any_io_executor>
class basic_stream {
    template <class Protocol1, class Executor1>
    friend class basic_connection;

    using stream_type = detail::stream_base<Protocol, Executor>;

private:
    std::shared_ptr<stream_type> base_;
    
public:

    SSL* native_handle() const {
        return base_->handle_;
    }

    template <class MutableBufferSequence>
    std::size_t read_some(const MutableBufferSequence& buffers) {
        std::size_t read = 0;
        for (auto i=boost::asio::buffer_sequence_begin(buffers); i!=boost::asio::buffer_sequence_end(buffers); ++i) {
            boost::asio::mutable_buffer buffer = *i;
            std::size_t size;
            if (int r = SSL_read_ex(base_->handle_, buffer.data(), buffer.size(), &size); r <= 0) {
                throw boost::system::system_error(SSL_get_error(base_->handle_, r), boost::asio::error::get_ssl_category());
            }
            read += size;
            if (size != buffer.size()) {
                break;
            }
        }
        return read;
    }

    template <class ConstBufferSequence>
    std::size_t write_some(const ConstBufferSequence& buffers) {
        std::size_t write = 0;
        for (auto i=boost::asio::buffer_sequence_begin(buffers); i!=boost::asio::buffer_sequence_end(buffers); ++i) {
            boost::asio::const_buffer buffer = *i;
            std::size_t size;
            if (int r = SSL_write_ex(base_->handle_, buffer.data(), buffer.size(), &size); r <= 0) {
                throw boost::system::system_error(SSL_get_error(base_->handle_, r), boost::asio::error::get_ssl_category());
            }
            write += size;
            // 默认情况 SSL_MODE_ENABLE_PARTIAL_WRITE 未启用，未发生错误时一定完成了写入
        }
        return write;
    }

    void shutdown(boost::asio::socket_base::shutdown_type what) {
        switch (what) {
        case boost::asio::socket_base::shutdown_both:
            [[fallthrough]];
        case boost::asio::socket_base::shutdown_send:
            if (int r = SSL_stream_conclude(base_->handle_, 0); r != 1) {
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
