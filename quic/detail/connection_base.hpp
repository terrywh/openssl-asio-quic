#ifndef QUIC_DETAIL_SOCKET_EVENT_H
#define QUIC_DETAIL_SOCKET_EVENT_H

#include "ssl.hpp"
#include "asio.hpp"
#include "../alpn.hpp"
#include "../basic_endpoint.hpp"
#include "extra_data.hpp"

#include <chrono>
#include <vector>

namespace quic {
namespace detail {

template <class Protocol, class Executor>
struct connection_base {

    using executor_type = boost::asio::strand<Executor>;
    using endpoint_type = typename boost::asio::basic_socket<Protocol, Executor>::endpoint_type;


    boost::asio::strand<Executor>                strand_;
    boost::asio::ssl::context&                   sslctx_;

    SSL*                                         handle_;
    boost::asio::basic_datagram_socket<Protocol> socket_;
    boost::asio::steady_timer                     timer_;
    std::vector<boost::asio::any_completion_handler<void (boost::system::error_code)>> waitable_;
    std::vector<boost::asio::any_completion_handler<void (boost::system::error_code)>> callable_;

    application_protocol_list alpn_;
    std::string               host_;

    template <class ExecutorContext>
    connection_base(ExecutorContext& ex, boost::asio::ssl::context& ctx)
    : strand_(ex.get_executor()) 
    , sslctx_(ctx) 
    , handle_(nullptr)
    , socket_(strand_)
    , timer_(strand_) {
        callable_.reserve(4);
        waitable_.reserve(4);
        set_alpn(application_protocol_list{"default/1"});
        set_host("localhost");
    }

    void add_ref() {
        SSL_up_ref(handle_);
    }
    // 引用数降为零时，将删除当前对象
    void del_ref() {
        SSL_free(handle_); 
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

        auto us = get_timeout();
        timer_.expires_after(us);
        timer_.async_wait(boost::asio::bind_executor(strand_, [this] (boost::system::error_code error) {
            if (error) return;
            
            invoke_waitable(error);
            socket_.cancel();
        }));
    }


    std::chrono::steady_clock::duration get_timeout() {
        struct timeval tv;
        int isinfinite;
        std::chrono::microseconds us { 8000 };
        if (SSL_get_event_timeout(handle_, &tv, &isinfinite) && !isinfinite
            /* && tv.tv_sec < 1 && tv.tv_usec < 8000 */)
            us = std::chrono::microseconds(tv.tv_usec + tv.tv_sec * 1000000);
        return us;
    }

    void set_alpn(const application_protocol_list& alpn) {
        alpn_ = alpn;
    }

    void set_host(const std::string& host) {
        host_ = host;
    }
};

} // namespace detail
} // namespace quic

#endif // QUIC_DETAIL_SOCKET_EVENT_H
