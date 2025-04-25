#ifndef BOOST_ASIO_QUIC_BASIC_SERVER_H
#define BOOST_ASIO_QUIC_BASIC_SERVER_H

#include "detail/stream_base.hpp"
#include "detail/do_write_some.hpp"
#include "detail/do_read_some.hpp"

namespace quic {

template <class Protocol, class Executor>
class basic_connection;

template <class Protocol, class Executor = boost::asio::any_io_executor>
class basic_stream {
public:
    template <class Protocol1, class Executor1>
    friend class basic_connection;

    using connection_type = detail::connection_base<Protocol, Executor>;
    using executor_type = connection_type::executor_type;
    using stream_type = detail::stream_base<Protocol, Executor>;

private:
    std::shared_ptr<connection_type> conn_;
    std::shared_ptr<stream_type> base_;
    
public:
    executor_type& get_executor() const {
        return base_->conn_->strand_;
    }

    SSL* native_handle() const {
        return base_->handle_;
    }

    template <class MutableBufferSequence>
    std::size_t read_some(const MutableBufferSequence& buffers) {
       return detail::do_read_some<Protocol, Executor, MutableBufferSequence>{conn_.get(), base_.get(), buffers}();
    }

    template <class MutableBufferSequence, class CompletionToken>
    auto async_read_some(const MutableBufferSequence& buffers, CompletionToken&& token) {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)>(
            detail::do_async_read_some<Protocol, Executor, MutableBufferSequence>{
                conn_.get(), base_.get(), buffers}, token);
    }

    template <class ConstBufferSequence>
    std::size_t write_some(const ConstBufferSequence& buffers) {
        return detail::do_write_some<Protocol, Executor, ConstBufferSequence>{conn_.get(), base_.get(), buffers}();
    }

    template <class ConstBufferSequence, class CompletionToken>
    auto async_write_some(const ConstBufferSequence& buffers, CompletionToken&& token) {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)>(
            detail::do_async_write_some<Protocol, Executor, ConstBufferSequence>{
                conn_.get(), base_.get(), buffers}, token);
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
