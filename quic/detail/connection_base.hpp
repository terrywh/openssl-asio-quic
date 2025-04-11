#ifndef QUIC_DETAIL_SOCKET_EVENT_H
#define QUIC_DETAIL_SOCKET_EVENT_H

#include "ssl.hpp"
#include "asio.hpp"
#include "../alpn.hpp"
#include "../basic_endpoint.hpp"
#include "../proto.hpp"

#include <boost/asio/any_completion_handler.hpp>
#include <chrono>

namespace quic {
namespace detail {

template <class Protocol, class Executor>
class connection_base {
    template <class Protocol1, class Executor1>
    friend class do_async_connect;
    template <class Protocol1, class Executor1, class EndpointSequence>
    friend class do_async_connect_seq;

    template <class Protocol1, class Executor1, class EndpointSequence>
    friend class do_connect_seq;
public:
    using executor_type = boost::asio::strand<Executor>;
    using endpoint_type = typename boost::asio::basic_socket<Protocol, Executor>::endpoint_type;


private:
    std::vector<boost::asio::any_completion_handler<void (boost::system::error_code)>> waitable_;
    application_protocol_list alpn_;
    std::string               host_;


protected:
    boost::asio::ssl::context& ctx_;
    boost::asio::strand<Executor> strand_;
    boost::asio::basic_datagram_socket<Protocol> socket_;
    boost::asio::steady_timer timer_;
    SSL* ssl_;

    template <class ExecutorContext>
    connection_base(boost::asio::ssl::context& ctx, ExecutorContext& ex, SSL* conn)
    : ctx_(ctx) 
    , strand_(ex.get_executor()) 
    , socket_(ex.get_executor())
    , timer_(strand_) 
    , ssl_(conn) {
        waitable_.reserve(8);
        alpn_ = application_protocol_list{"default/1"};
        host_ = "localhost";
    }

    ~connection_base() {
        if (ssl_) {
            SSL_free(ssl_);
            ssl_ = nullptr;
        }
    }

    void create_ssl(const endpoint_type& addr, bool nonblocking) {
        BOOST_ASSERT(this->socket_.is_open());

        if (nonblocking)
            this->socket_.native_non_blocking(true);

        ssl_ = SSL_new(ctx_.native_handle());
        SSL_set_default_stream_mode(ssl_, SSL_DEFAULT_STREAM_MODE_NONE);


        BIO* bio = BIO_new(BIO_s_datagram());
        BIO_set_fd(bio, this->socket_.native_handle(), BIO_NOCLOSE);
        SSL_set_bio(ssl_, bio, bio);

        SSL_set_tlsext_host_name(ssl_, host_.c_str());
        SSL_set1_host(ssl_, host_.c_str());
        SSL_set_alpn_protos(ssl_, alpn_, alpn_.size());
        SSL_set1_initial_peer_addr(ssl_, addr);

        if (nonblocking)
            SSL_set_blocking_mode(ssl_, 0);
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

    void on_waitable(boost::asio::any_completion_handler<void (boost::system::error_code)> op) {
        boost::asio::post(strand_, [this, op = std::move(op)] () mutable {
            int w = SSL_net_write_desired(ssl_),
                r = SSL_net_read_desired(ssl_);

            if (r || w) {
                waitable_.push_back(std::move(op));
                
                if (waitable_.size() == 1 && w)
                    this->socket_.async_wait(boost::asio::socket_base::wait_write, boost::asio::bind_executor(strand_, 
                        [this] (boost::system::error_code error) {
                            if (ssl_ == nullptr) return;
                            if (error == boost::asio::error::operation_aborted) {
                                error = {};
                            }
                            for (auto& op : waitable_) {
                                op(error);
                            }
                            waitable_.clear();
                        }));
                
                else if (waitable_.size() == 1 && r)
                    this->socket_.async_wait(boost::asio::socket_base::wait_read, boost::asio::bind_executor(strand_, 
                        [this] (boost::system::error_code error) {
                            if (ssl_ == nullptr) return;
                            if (error == boost::asio::error::operation_aborted) {
                                error = {};
                            }
                            while (!waitable_.empty()) {
                                waitable_.back()(error);
                                waitable_.pop_back();
                            }
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
    boost::system::error_code handle_error(int r, Handler&& h) {
        int err = SSL_get_error(this->ssl_, r);

        switch (err) {
        case SSL_ERROR_WANT_READ:
            [[fallthrough]];
        case SSL_ERROR_WANT_WRITE:
            if (auto us = get_timeout(); us > std::chrono::microseconds(0))
                on_timeout(us);
            
            on_waitable(std::move(h));
            // on_waitable(detail::operation_wrapper{
            //     // 注意将 std::move 后置
            //     // 似乎其存在某种奇怪的副作用，目前没搞懂；
            //     detail::operation<Handler, std::allocator<std::byte>>::create(std::move(h))
            // });
            return {};
        default:
            return {err, boost::asio::error::get_ssl_category()};
        }
    }

public:
    void set_alpn(const application_protocol_list& alpn) {
        alpn_ = alpn;
    }

    void set_host(const std::string& host) {
        host_ = host;
    }

    executor_type get_executor() {
        return this->strand_;
    }

};

} // namespace detail
} // namespace quic

#endif // QUIC_DETAIL_SOCKET_EVENT_H
