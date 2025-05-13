#ifndef QUIC_IMPL_WAITABLE_H
#define QUIC_IMPL_WAITABLE_H

#include "../detail/asio.hpp"
#include "../proto.hpp"
#include <vector>

namespace quic {
namespace impl {

class waitable {
    std::vector<boost::asio::any_completion_handler<void (boost::system::error_code)>> waitable_;
    std::vector<boost::asio::any_completion_handler<void (boost::system::error_code)>> callable_;

public:
    boost::asio::strand<boost::asio::io_context::executor_type> strand_;
    boost::asio::basic_datagram_socket<quic::proto> socket_;
    boost::asio::steady_timer timer_;
    SSL* handle_;

    template <class Executor>
    waitable(const Executor& ex, SSL* handle)
    : strand_(ex)
    , socket_(strand_)
    , timer_(strand_)
    , handle_(handle) {
        callable_.reserve(4);
        waitable_.reserve(4);
    }

    void invoke_waitable(const boost::system::error_code& error) {
        callable_.swap(waitable_);
        while (!callable_.empty()) {
            auto handler = std::move(callable_.back());
            callable_.pop_back();
            handler(error); // handler 调用时可能对 waitable_ 追加
        }
    }

    void async_wait(boost::asio::any_completion_handler<void (boost::system::error_code)> handler) {
        waitable_.push_back(std::move(handler));
        if (waitable_.size() > 1) return;

        int w = SSL_net_write_desired(handle_),
            r = SSL_net_read_desired(handle_);

        if (w)
            socket_.async_wait(boost::asio::socket_base::wait_write, boost::asio::bind_executor(strand_,
                    [this] (boost::system::error_code error) {
                if (error) return;
                invoke_waitable(error);
            }));

        if (r)
            socket_.async_wait(boost::asio::socket_base::wait_read, boost::asio::bind_executor(strand_,
                [this] (boost::system::error_code error) {
                if (error) return;
                invoke_waitable(error);
            }));

        auto us = timeout();
        timer_.expires_after(us);
        timer_.async_wait(boost::asio::bind_executor(strand_, [this] (boost::system::error_code error) {
            if (error) return;

            // SSL_handle_events(ssl);
            invoke_waitable(error);
            socket_.cancel();
        }));
    }

    std::chrono::steady_clock::duration timeout() {
        struct timeval tv;
        int isinfinite;
        std::chrono::microseconds us { 8000 };
        if (SSL_get_event_timeout(handle_, &tv, &isinfinite) && !isinfinite)
            us = std::chrono::microseconds(tv.tv_usec + tv.tv_sec * 1000000);
        return us;
    }
};

} // namespace impl
} // namespace quic

#endif // QUIC_IMPL_WAITABLE_H