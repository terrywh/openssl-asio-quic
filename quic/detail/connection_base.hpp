#ifndef QUIC_DETAIL_SOCKET_EVENT_H
#define QUIC_DETAIL_SOCKET_EVENT_H

#include "ssl.hpp"
#include "asio.hpp"
#include "../alpn.hpp"
#include "../basic_endpoint.hpp"
#include "../proto.hpp"
#include "extra_data.hpp"

#include <boost/asio/any_completion_handler.hpp>
#include <boost/asio/immediate.hpp>

#include <chrono>
#include <iostream>
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

    application_protocol_list alpn_;
    std::string               host_;

    template <class ExecutorContext>
    connection_base(ExecutorContext& ex, boost::asio::ssl::context& ctx)
    : strand_(ex.get_executor()) 
    , sslctx_(ctx) 
    , handle_(nullptr)
    , socket_(strand_)
    , timer_(strand_) {
        waitable_.reserve(8);
        set_alpn(application_protocol_list{"default/1"});
        set_host("localhost");
    }

    ~connection_base() {
        std::cout << "~connection_base\n";
    }

    void add_ref() {
        SSL_up_ref(handle_);
    }
    // 引用数降为零时，将删除当前对象
    void del_ref() {
        SSL_free(handle_); 
    }

    void on_timeout(std::chrono::steady_clock::duration us) {
        boost::asio::post(strand_, [this, us] () mutable {
            timer_.expires_after(us);
            timer_.async_wait(boost::asio::bind_executor(strand_, [this] (boost::system::error_code error) {
                if (error) return;
                this->socket_.cancel();
            }));
        });
    }

    void on_waitable(boost::asio::any_completion_handler<void (boost::system::error_code)> handler) {
        int w = SSL_net_write_desired(handle_),
            r = SSL_net_read_desired(handle_);

        if (r || w) {
            waitable_.push_back(std::move(handler));

            if (waitable_.size() == 1 && w)
                this->socket_.async_wait(boost::asio::socket_base::wait_write, boost::asio::bind_executor(strand_, 
                    [this] (boost::system::error_code error) {
                        if (error == boost::asio::error::operation_aborted) {
                            error = {};
                        }
                        while (!waitable_.empty()) {
                            auto handler = std::move(waitable_.back());
                            waitable_.pop_back();
                            handler(error);
                        }
                    }));
            
            else if (waitable_.size() == 1 && r)
                this->socket_.async_wait(boost::asio::socket_base::wait_read, boost::asio::bind_executor(strand_, 
                    [this] (boost::system::error_code error) {
                        if (error == boost::asio::error::operation_aborted) {
                            error = {};
                        }
                        while (!waitable_.empty()) {
                            auto handler = std::move(waitable_.back());
                            waitable_.pop_back();
                            handler(error); // 调用时存在 std::move 逻辑，避免直接在 waitable_ 内调用
                            //（否则可能导致某种内存问题，如 bad_function_call 等问题；
                        }
                    }));
        }
    }


    std::chrono::steady_clock::duration get_timeout() {
        struct timeval tv;
        int isinfinite;
        std::chrono::microseconds us { 0 };
        if (SSL_get_event_timeout(handle_, &tv, &isinfinite) && !isinfinite) 
            us = std::chrono::microseconds(tv.tv_usec + tv.tv_sec * 1000000);
        
        return us < std::chrono::milliseconds(8) ? us : std::chrono::microseconds(0);
    }
   

    template <class Handler>
    void async_handle_error(int r, Handler&& handler) {
        int err = SSL_get_error(handle_, r);

        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            if (auto us = get_timeout(); us > std::chrono::microseconds(0))
                on_timeout(us);
            on_waitable(std::move(handler));
        } else {
            boost::asio::post(strand_, [handler = std::move(handler), err] () mutable {
                handler(boost::system::error_code{err, boost::asio::error::get_ssl_category()});
            });
        }
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
