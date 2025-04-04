#ifndef ASIO_QUIC_BASIC_CONNECTION_H
#define ASIO_QUIC_BASIC_CONNECTION_H

#include "detail/asio.hpp"
#include "detail/ssl.hpp"
#include "detail/operation.hpp"
#include "alpn.hpp"
#include "basic_endpoint.hpp"
#include "basic_stream.hpp"

#include <iostream>

namespace quic {

template <class Protocol, class Executor = boost::asio::any_io_executor>
class basic_connection {
public:
    using protocol_type = typename std::decay<Protocol>::type;
    using executor_type = typename std::decay<Executor>::type;
    using endpoint_type = basic_endpoint<Protocol>;
    using socket_type = boost::asio::basic_datagram_socket<Protocol, Executor>;
    using stream_type = basic_stream<Protocol, Executor>;

private:
    boost::asio::ssl::context& ctx_;
    boost::asio::strand<Executor> strand_;
    boost::asio::steady_timer timer_;
    socket_type socket_;
    SSL* ssl_;


    std::vector<detail::operation_wrapper> readable_;
    std::vector<detail::operation_wrapper> writable_;
    

    template <class Executor1>
    basic_connection(boost::asio::ssl::context& ctx, const Executor1& ex, SSL* conn)
    : ctx_(ctx) 
    , strand_(ex) 
    , timer_(strand_) 
    , socket_(strand_)
    , ssl_(conn) {
        readable_.reserve(8);
        writable_.reserve(8);
    }

    basic_connection(basic_connection&& conn) = delete;
    basic_connection(const basic_connection& conn) = delete;

    void create_ssl(const endpoint_type& addr,
        const std::string& host, const application_protocol_list& alpn, bool nonblocking) {
        BOOST_ASSERT(socket_.is_open());
    
        BIO* bio = BIO_new(BIO_s_datagram());
        BIO_set_fd(bio, socket_.native_handle(), BIO_NOCLOSE);

        ssl_ = SSL_new(ctx_.native_handle());
        SSL_set_bio(ssl_, bio, bio);
        
        SSL_set_default_stream_mode(ssl_, SSL_DEFAULT_STREAM_MODE_NONE);
       

        SSL_set_tlsext_host_name(ssl_, host.c_str());
        SSL_set1_host(ssl_, host.c_str());
        SSL_set_alpn_protos(ssl_, alpn, alpn.size());
        SSL_set1_initial_peer_addr(ssl_, addr);

        if (nonblocking) {
            socket_.native_non_blocking(true);
            SSL_set_blocking_mode(ssl_, 0);
        }
    }



    void on_readable(detail::operation_wrapper&& op) {
        boost::asio::post(strand_, [this, op = std::move(op)] () mutable {
            readable_.push_back(std::move(op));
            if (readable_.size() == 1) {
                socket_.async_wait(boost::asio::socket_base::wait_read, boost::asio::bind_executor(strand_, 
                    [this] (boost::system::error_code error) {
                        for (auto& rop: readable_) {
                            std::move(rop)(error);
                        }
                        readable_.clear();
                    }));
            }
        });
    }

    void on_writable(detail::operation_wrapper&& op) {
        boost::asio::post(strand_, [this, op = std::move(op)] () mutable {
            writable_.push_back(std::move(op));
            if (writable_.size() == 1) {
                socket_.async_wait(boost::asio::socket_base::wait_write, boost::asio::bind_executor(strand_, 
                    [this] (boost::system::error_code error) {
                        for (auto& wop : writable_) {
                            std::move(wop)(error);
                        }
                        writable_.clear();
                    }));
            }
        });
    }

   

    template <class Handler>
    void handle_error(int r, Handler&& h) {
        struct defer {
            defer () {
                std::cout << "handle_error start:\n";
            }
            ~defer () {
                std::cout << "handle_error end\n";
            }
        } defer;
        detail::operation_wrapper op { detail::operation<Handler, std::allocator<std::byte>>::create(std::move(h)) };

        int err = SSL_get_error(this->ssl_, r);

        switch (err) {
        case SSL_ERROR_WANT_READ:
            on_readable(std::move(op));
            break;
        case SSL_ERROR_WANT_WRITE:
            on_writable(std::move(op));
            break;
        default:
            boost::asio::post(strand_, [err, op = std::move(op)] () mutable {
                std::move(op)(boost::system::error_code{err, boost::asio::error::get_ssl_category()});
            });
        }
        
    }


public:
    template <class Executor1>
    basic_connection(boost::asio::ssl::context& ctx, const Executor1& ex)
    : basic_connection(ctx, ex, nullptr) {
    }

    ~basic_connection() {
        std::cout << "connection destroy\n";
    }

    void connect(const endpoint_type& addr, const std::string& host, application_protocol_list& alpn) {
        this->socket_.connect(addr);
        this->create_ssl(addr, host, alpn, false);
        // TLS 协议握手
        if (int r = SSL_connect(this->ssl_); r <= 0) {
            throw boost::system::system_error(SSL_get_error(this->ssl_, r), boost::asio::error::get_ssl_category());
        }
    }

    template <class CompletionToken>
    auto async_connect(const std::string& host, const endpoint_type& addr, application_protocol_list& alpn,
        CompletionToken&& token) {


        auto initiate = [] (
            auto&& handler,
            basic_connection<Protocol, Executor>& conn,
            const endpoint_type& addr, const std::string& host, application_protocol_list& alpn) {

            struct connect_impl {
                using handler_type = typename std::decay<decltype(handler)>::type;
                handler_type handler_;
                basic_connection<Protocol, Executor>& conn_;
                const endpoint_type& addr_;
                const std::string& host_;
                application_protocol_list& alpn_;
                
                connect_impl(handler_type&& handler, basic_connection<Protocol, Executor>& conn,
                    const endpoint_type& addr, const std::string& host, application_protocol_list& alpn)
                : handler_(std::move(handler))
                , conn_(conn)
                , addr_(addr)
                , host_(host)
                , alpn_(alpn) {

                    std::cout << "connect_impl +++\n";
                }

                connect_impl(const connect_impl& impl) = delete;
                connect_impl(connect_impl&& impl)
                : handler_(std::move(impl.handler_))
                , conn_(impl.conn_)
                , addr_(impl.addr_)
                , host_(impl.host_)
                , alpn_(impl.alpn_) {
                    std::cout << "connect_impl ===\n";
                }

                ~connect_impl() {
                    std::cout << "connect_impl ---\n";
                }

                enum {starting, creating, handshaking, done} state_ = starting;

                void operator()(boost::system::error_code error) {
                        
                CONTINUE:
                    switch(state_) {
                    case starting:
                        conn_.create_ssl(addr_, host_, alpn_, true);
                        state_ = handshaking;
                        goto CONTINUE;
                        // break;
                    case handshaking:
                        if (error) {
                            handler_(error);
                            return;
                        }
                        BOOST_ASSERT(conn_.socket_.is_open());
                        if (int r = SSL_connect(conn_.ssl_); r <= 0) {
                            conn_.handle_error(r, std::move(*this));
                        } else {
                            std::move(handler_)(error);
                        }
                        
                    }
                }
            };

            // conn.socket_.async_connect(addr, connect_impl{
            //     std::move(completion_handler), std::ref(conn), addr, host, alpn});
            conn.socket_.async_connect(addr, connect_impl{std::move(handler), conn, addr, host, alpn});
        };
        return boost::asio::async_initiate<CompletionToken, void (boost::system::error_code)>(initiate,
            std::move(token), std::ref(*this), std::ref(addr), std::ref(host), std::ref(alpn));
    }

    stream_type accept_stream() {
        if (SSL* stream = SSL_accept_stream(this->ssl_, 0); stream == nullptr) {
            throw boost::system::system_error(SSL_get_error(ssl_, 0), boost::asio::error::get_ssl_category());
        } else {
            return {*this, stream};
        }
    }

    // using do_accept_stream = detail::accept_stream_impl<protocol_type, executor_type>;
    // template <class CompletionToken>
    // auto async_accept_stream(basic_stream<Protocol, Executor>& stream, CompletionToken&& token) -> decltype(
    //     boost::asio::async_compose<CompletionToken, void(boost::system::error_code, stream_type)>(
    //         std::declval<do_accept_stream>(), token, this->socket_)) {
        
    //     return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, stream_type)>(
    //         do_accept_stream{*this->conn_, stream}, token, this->socket_);
    // }

    stream_type create_stream() {
        if (SSL* ssl = SSL_new_stream(this->ssl_, 0); ssl == nullptr) {
            throw boost::system::system_error(SSL_get_error(this->ssl_, 0), boost::asio::error::get_ssl_category());
        } else {
            return {*this, ssl};
        }
    }

    // using do_create_stream = detail::create_stream_impl<protocol_type, executor_type>;

    // template <class Executor1, class CompletionToken>
    // auto async_create_stream(basic_stream<Protocol, Executor1>& stream, CompletionToken&& token) ->
    //     decltype(boost::asio::async_compose<CompletionToken, void(boost::system::error_code)>(
    //         std::declval<do_create_stream>(), this->socket_
    //     )) {
    //     return boost::asio::async_compose<CompletionToken, void(boost::system::error_code)>(
    //         do_create_stream{*this, stream}, this->socket_);
    // }

    template <class Protocol1, class Executor1>
    friend class basic_server;
};

} // namespace quic

#endif // ASIO_QUIC_BASIC_CONNECTION_H
