#ifndef QUIC_DETAIL_CONNECT_H
#define QUIC_DETAIL_CONNECT_H

#include "connection_base.hpp"
#include "../basic_endpoint.hpp"
#include "../alpn.hpp"

namespace quic {

template <class Protocol, class Executor>
class basic_connection;

namespace detail {

template <class Protocol, class Executor>
struct do_connect_base {
    using connection_type = connection_base<Protocol, Executor>;
    using endpoint_type = connection_type::endpoint_type;

    connection_base<Protocol, Executor>* conn_;
    endpoint_type addr_;

    do_connect_base(connection_base<Protocol, Executor>* conn, const endpoint_type& addr)
    : conn_(conn)
    , addr_(addr) {}

    void create(bool blocking) const {
        conn_->handle_ = SSL_new(conn_->sslctx_.native_handle());
        SSL_set_default_stream_mode(conn_->handle_, SSL_DEFAULT_STREAM_MODE_NONE);
        extra_data<connection_type>::attach(conn_->handle_, conn_);

        SSL_set_alpn_protos(conn_->handle_, conn_->alpn_, conn_->alpn_.size());
        SSL_set_tlsext_host_name(conn_->handle_, conn_->host_.c_str());
        SSL_set1_host(conn_->handle_, conn_->host_.c_str());
        ERR_print_errors_fp(stderr);

        BIO* bio = BIO_new(BIO_s_datagram());
        BOOST_ASSERT(conn_->socket_.is_open());
        BIO_set_fd(bio, conn_->socket_.native_handle(), BIO_NOCLOSE);
        SSL_set_bio(conn_->handle_, bio, bio);
        ERR_print_errors_fp(stderr);

        SSL_set1_initial_peer_addr(conn_->handle_, addr_);
    }
};

template <class Protocol, class Executor>
struct do_connect: public do_connect_base<Protocol, Executor> {
    using connection_type = typename do_connect_base<Protocol, Executor>::connection_type;
    using endpoint_type = typename do_connect_base<Protocol, Executor>::endpoint_type;

    do_connect(connection_type* conn, const endpoint_type& addr)
    : do_connect_base<Protocol,Executor>(conn, addr) {}

    void operator()() const {
        extra_data<connection_type>::detach(this->conn_->handle_);
        SSL_free(this->conn_->handle_);
        this->conn_->socket_.connect(this->addr_);
        this->create(true);

        if (int r = SSL_connect(this->conn_->handle_); r <= 0) {
            this->conn_->socket_.close();
            ERR_print_errors_fp(stderr);
            throw boost::system::system_error(SSL_get_error(this->conn_->handle_, r), boost::asio::error::get_ssl_category());
        }
    }
};

template <class Protocol, class Executor>
struct do_async_connect: public do_connect_base<Protocol, Executor> {
    using connection_type = typename do_connect_base<Protocol, Executor>::connection_type;
    using endpoint_type = typename do_connect_base<Protocol, Executor>::endpoint_type;

    mutable enum {connecting, binding, handshaking} state_;
    
    do_async_connect(connection_base<Protocol, Executor>* conn, const endpoint_type& addr)
    : do_connect_base<Protocol,Executor>(conn, addr)
    , state_(connecting) { }

    template <class Self>
    void operator ()(Self& self, boost::system::error_code error = {}) const {
        if (error) {
            boost::asio::post(this->conn_->strand_, [self = std::move(self), error] () mutable {
                self.complete(error);
            });
            return;
        }

        switch (state_) {
        case connecting: 
            state_ = binding;
            this->conn_->socket_.native_non_blocking(true);
            this->conn_->socket_.async_connect(this->addr_, std::move(self));
            break;
        case binding:
            state_ = handshaking;
            BOOST_ASSERT(this->conn_->socket_.is_open());
            this->create(false);
            SSL_set_blocking_mode(this->conn_->handle_, 0);

            [[fallthrough]];
        case handshaking:
            if (int r = SSL_connect(this->conn_->handle_); r != 1) {
                this->conn_->async_handle_error(r, std::move(self));
            } else {
                boost::asio::post(this->conn_->strand_, [self = std::move(self)] () mutable {
                    self.complete(boost::system::error_code{});
                });
            }
        }
    }
};

template <class Protocol, class Executor, class EndpointSequence>
struct do_async_connect_seq {
    using endpoint_seq = typename std::decay<EndpointSequence>::type;
    using iterator_type = typename EndpointSequence::iterator;
    using difference_type = iterator_type::difference_type;
   
    connection_base<Protocol, Executor>* conn_;
    endpoint_seq addr_;
    mutable difference_type start_;

    do_async_connect_seq(connection_base<Protocol, Executor>* conn, const EndpointSequence& addr)
    : conn_(conn)
    , addr_(addr)
    , start_(0) {}

    do_async_connect_seq(const do_async_connect_seq& seq) = delete;
    do_async_connect_seq(do_async_connect_seq&& seq) = default;

    template <class Self>
    void operator()(Self& self, boost::system::error_code error = {}) const {
        if (!error && start_ > 0) {
            boost::asio::post(conn_->strand_, [self = std::move(self), error] () mutable {
                self.complete(error);
            });
            return;
        }

        iterator_type i = addr_.begin();
        std::advance(i, start_++);

        if (i == addr_.end()) {
            boost::asio::post(conn_->strand_, [self = std::move(self)] () mutable {
                self.complete(boost::system::error_code{
                    boost::asio::error::host_unreachable, boost::asio::error::get_system_category()});
            });
            return;
        }

        boost::asio::async_compose<Self, void (boost::system::error_code)>(
            detail::do_async_connect{conn_, *i}, self);
    }
};

template <class Protocol, class Executor, class EndpointSequence>
struct do_connect_seq {
    using endpoint_seq = typename std::decay<EndpointSequence>::type;
    using endpoint_type = typename EndpointSequence::value_type;


    connection_base<Protocol, Executor>* conn_;
    EndpointSequence addr_;

    do_connect_seq(connection_base<Protocol, Executor>* conn, const EndpointSequence& eps)
    : conn_(conn)
    , addr_(eps) {}

    endpoint_type operator()() {
        for (const auto& addr : addr_) {
            try {
                do_connect<Protocol, Executor>{conn_, addr}();
            } catch(const std::exception& ex) {
                std::cerr << ex.what() << "\n";
                continue;
            }
            return addr;
        }
        throw boost::system::system_error(boost::asio::error::host_unreachable, boost::asio::error::get_system_category());
        // boost::system::error_code{
        //     boost::asio::error::host_unreachable, boost::asio::error::get_netdb_category()});
    }
};


} // namespace detail
} // namespace quic

#endif // QUIC_DETAIL_CONNECT_H
