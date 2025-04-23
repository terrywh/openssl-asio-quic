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
struct do_connect {
    connection_base<Protocol, Executor>* conn_;
    using endpoint_type = typename connection_base<Protocol, Executor>::endpoint_type;
    endpoint_type addr_;

    do_connect(connection_base<Protocol, Executor>* conn, const endpoint_type& addr)
    : conn_(conn)
    , addr_(addr) {}

    void operator()() const {
        conn_->socket_.connect(addr_);

        BIO* bio = BIO_new(BIO_s_datagram());
        BIO_set_fd(bio, conn_->socket_.native_handle(), BIO_NOCLOSE);
        SSL_set_bio(conn_->handle_, bio, bio);

        if (int r = SSL_connect(conn_->handle_); r <= 0) {
            throw boost::system::system_error(SSL_get_error(conn_->handle_, r), boost::asio::error::get_ssl_category());
        }
    }
};

template <class Protocol, class Executor>
struct do_async_connect {
    using endpoint_type = typename connection_base<Protocol, Executor>::endpoint_type;

    connection_base<Protocol, Executor>* conn_;
    
    endpoint_type addr_;
    mutable enum {connecting, binding, handshaking} state_;
    
    do_async_connect(connection_base<Protocol, Executor>* conn, const endpoint_type& addr)
    : conn_(conn)
    , addr_(addr) 
    , state_(connecting) {
       
    }

    do_async_connect(const do_async_connect& impl) = delete;
    do_async_connect(do_async_connect&& impl) = default;

    void bind() const {
        BIO* bio = BIO_new(BIO_s_datagram());
        BIO_set_fd(bio, conn_->socket_.native_handle(), BIO_NOCLOSE);
        SSL_set_bio(conn_->handle_, bio, bio);
    }

    template <class Self>
    void operator ()(Self& self, boost::system::error_code error = {}) const {
        if (error) {
            boost::asio::post(conn_->strand_, [self = std::move(self), error] () mutable {
                self.complete(error);
            });
            return;
        }

        switch (state_) {
        case connecting: 
            state_ = binding;
            SSL_set1_initial_peer_addr(conn_->handle_, addr_);
            conn_->socket_.async_connect(addr_, std::move(self));
            break;
        case binding:
            state_ = handshaking;

            BOOST_ASSERT(conn_->socket_.is_open());
            conn_->socket_.native_non_blocking(true);
            bind();

            [[fallthrough]];
        case handshaking:
            if (int r = SSL_connect(conn_->handle_); r != 1) {
                conn_->async_handle_error(r, std::move(self));
            } else {
                boost::asio::post(conn_->strand_, [self = std::move(self)] () mutable {
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
                    boost::asio::error::host_unreachable, boost::asio::error::get_netdb_category()});
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
                do_connect{conn_, addr}();
            } catch(...) {
                continue;
            }
            break;
        }
        throw boost::system::system_error(boost::asio::error::host_unreachable, boost::asio::error::get_netdb_category());
        // boost::system::error_code{
        //     boost::asio::error::host_unreachable, boost::asio::error::get_netdb_category()});
    }
};


} // namespace detail
} // namespace quic

#endif // QUIC_DETAIL_CONNECT_H
