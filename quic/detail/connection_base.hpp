#ifndef QUIC_DETAIL_SOCKET_EVENT_H
#define QUIC_DETAIL_SOCKET_EVENT_H

#include "ssl.hpp"
#include "asio.hpp"
#include "../alpn.hpp"
#include "../basic_endpoint.hpp"
#include "../proto.hpp"
#include "operation.hpp"

#include <chrono>

namespace quic {
namespace detail {

template <class Protocol, class Executor>
class connection_base {
    template <class Protocol1, class Executor1, class CompleteToken>
    friend class do_connect;

public:
    using socket_type = boost::asio::basic_datagram_socket<Protocol, Executor>;
    using protocol_type = typename std::decay<Protocol>::type;
    using executor_type = boost::asio::strand<Executor>;
    using endpoint_type = basic_endpoint<Protocol>;


private:
    std::vector<detail::operation_wrapper> waitable_;


protected:
    boost::asio::ssl::context& ctx_;
    boost::asio::strand<Executor> strand_;
    boost::asio::steady_timer timer_;
    socket_type socket_;
    SSL* ssl_;

    template <class ExecutorContext>
    connection_base(boost::asio::ssl::context& ctx, ExecutorContext& ex, SSL* conn)
    : ctx_(ctx) 
    , strand_(ex.get_executor()) 
    , timer_(strand_) 
    , socket_(strand_)
    , ssl_(conn) {
        waitable_.reserve(8);
    }

    void create_ssl(const endpoint_type& addr,
        const std::string& host, const application_protocol_list& alpn, bool nonblocking) {
        BOOST_ASSERT(socket_.is_open());

        if (nonblocking)
            socket_.native_non_blocking(true);
            // BIO_socket_nbio(socket_.native_handle(), 1);


        ssl_ = SSL_new(ctx_.native_handle());
        SSL_set_default_stream_mode(ssl_, SSL_DEFAULT_STREAM_MODE_NONE);


        BIO* bio = BIO_new(BIO_s_datagram());
        BIO_set_fd(bio, socket_.native_handle(), BIO_NOCLOSE);
        SSL_set_bio(ssl_, bio, bio);

        SSL_set_tlsext_host_name(ssl_, host.c_str());
        SSL_set1_host(ssl_, host.c_str());
        SSL_set_alpn_protos(ssl_, alpn, alpn.size());
        SSL_set1_initial_peer_addr(ssl_, addr);

        if (nonblocking)
            SSL_set_blocking_mode(ssl_, 0);
    }

    void on_timeout(std::chrono::steady_clock::duration us) {
        boost::asio::post(strand_, [this, us] () mutable {
            timer_.expires_after(us);
            timer_.async_wait(boost::asio::bind_executor(strand_, [this] (boost::system::error_code error) {
                if (error) return;
                socket_.cancel();
            }));
        });
    }

    void on_waitable(detail::operation_wrapper&& op) {
        boost::asio::post(strand_, [this, op = std::move(op)] () mutable {
            int w = SSL_net_write_desired(ssl_),
                r = SSL_net_read_desired(ssl_);

            if (r || w) {
                waitable_.push_back(std::move(op));
                
                if (waitable_.size() == 1 && w)
                    socket_.async_wait(boost::asio::socket_base::wait_write, boost::asio::bind_executor(strand_, 
                        [this] (boost::system::error_code error) {
                            if (error == boost::asio::error::operation_aborted) error = {};
                            for (auto& op : waitable_) {
                                std::move(op)(error);
                            }
                            waitable_.clear();
                        }));
                
                if (waitable_.size() == 1 && r)
                    socket_.async_wait(boost::asio::socket_base::wait_read, boost::asio::bind_executor(strand_, 
                        [this] (boost::system::error_code error) {
                            if (error == boost::asio::error::operation_aborted) error = {};
                            for (auto& op: waitable_) {
                                std::move(op)(error);
                            }
                            waitable_.clear();
                        }));
            }
        });
    }


    std::chrono::steady_clock::duration get_timeout() {
        struct timeval tv;
        int isinfinite;
        std::chrono::microseconds us { 0 };
        if (SSL_get_event_timeout(ssl_, &tv, &isinfinite) && !isinfinite) 
            us = std::chrono::microseconds(tv.tv_usec + tv.tv_sec * 1000000);
        
        return us < std::chrono::milliseconds(8) ? us : std::chrono::microseconds(0);
    }
   

    template <class Handler>
    void handle_error(int r, Handler&& h) {
        int err = SSL_get_error(this->ssl_, r);
        std::cout << std::chrono::system_clock::now() << " handle (result = " << r << " error = " << err << ")\n";
        detail::operation_wrapper op { detail::operation<Handler, std::allocator<std::byte>>::create(std::move(h)) };

        switch (err) {
        case SSL_ERROR_WANT_READ:
            [[fallthrough]];
        case SSL_ERROR_WANT_WRITE:
            on_waitable(std::move(op));
            if (auto us = get_timeout(); us > std::chrono::microseconds(0))
                on_timeout(us);
            
            break;
        default:
            boost::asio::post(strand_, [err, op = std::move(op)] () mutable {
                std::move(op)(boost::system::error_code{err, boost::asio::error::get_ssl_category()});
            });
        }
        
    }

public:

    executor_type get_executor() {
        return this->strand_;
    }
};

} // namespace detail
} // namespace quic

#endif // QUIC_DETAIL_SOCKET_EVENT_H
