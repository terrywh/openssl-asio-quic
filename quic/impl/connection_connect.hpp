#ifndef QUIC_DETAIL_CONNECT_H
#define QUIC_DETAIL_CONNECT_H

#include "../detail/error_handler.hpp"
#include "../detail/ssl_extra_data.hpp"

#include "connection.hpp"

#include "../endpoint.hpp"
#include "../endpoint_resolve_result.hpp"
#include "../alpn.hpp"

namespace quic {
namespace impl {

struct connection_connect_basic {
    impl::connection* conn_;
    const endpoint&   addr_;

    connection_connect_basic(impl::connection* conn, const endpoint& addr)
    : conn_(conn)
    , addr_(addr) {}

    void create_object(bool blocking) const {
        conn_->handle_ = SSL_new(conn_->sslctx_.native_handle());
        detail::ssl_extra_data::set<impl::connection>(conn_->handle_, conn_);

        SSL_set_default_stream_mode(conn_->handle_, SSL_DEFAULT_STREAM_MODE_NONE);
        SSL_set_alpn_protos(conn_->handle_, conn_->alpn_, conn_->alpn_.size());
        SSL_set_tlsext_host_name(conn_->handle_, conn_->host_.c_str());
        SSL_set1_host(conn_->handle_, conn_->host_.c_str());
        SSL_set1_initial_peer_addr(conn_->handle_, addr_);

        BIO* bio = BIO_new(BIO_s_datagram());
        BIO_set_fd(bio, conn_->socket_.native_handle(), BIO_NOCLOSE);
        SSL_set_bio(conn_->handle_, bio, bio);
    }
};

struct connection_connect: public connection_connect_basic {
    connection_connect(impl::connection* conn, const endpoint& addr)
    : connection_connect_basic(conn, addr) {}

    void operator()() const {
        conn_->socket_.close();
        conn_->socket_.connect(addr_);

        SSL_free(conn_->handle_);
        create_object(true);

        if (int r = SSL_connect(conn_->handle_); r <= 0) {
            detail::error_handler(SSL_get_error(conn_->handle_, r)).throws();
            std::cout << "abc\n";
        }
    }
};

struct connection_connect_async: public connection_connect_basic {
    mutable enum {connecting, binding, handshaking} state_;

    connection_connect_async(impl::connection* conn, const endpoint& addr)
    : connection_connect_basic(conn, addr)
    , state_(connecting) { }

    template <class Self>
    void operator ()(Self& self, boost::system::error_code error = {}) const {
        if (error) {
            self.complete(error);
            return;
        }

        switch (state_) {
        case connecting:
            state_ = binding;
            conn_->socket_.close();
            conn_->socket_.async_connect(addr_, std::move(self));
            break;
        case binding:
            state_ = handshaking;
            conn_->socket_.native_non_blocking(true);

            SSL_free(conn_->handle_);
            create_object(false);
            SSL_set_blocking_mode(conn_->handle_, 0);

            [[fallthrough]];
        case handshaking:
            if (int r = SSL_connect(conn_->handle_); r != 1) {
                if (detail::error_handler(SSL_get_error(conn_->handle_, r)).returns(self)) 
                    conn_->async_wait(std::move(self));
            } else {
                self.complete(boost::system::error_code{});
            }
        }
    }
};

struct connection_connect_async_seq {
    using iterator_type = endpoint_resolve_result::iterator;
    using difference_type = iterator_type::difference_type;

    impl::connection*        conn_;
    endpoint_resolve_result  addr_;
    mutable difference_type start_;

    connection_connect_async_seq(impl::connection* conn, const endpoint_resolve_result& addr)
    : conn_(conn)
    , addr_(addr)
    , start_(0) {}

    connection_connect_async_seq(const connection_connect_async_seq& seq) = delete;
    connection_connect_async_seq(connection_connect_async_seq&& seq) = default;

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
            boost::asio::post(conn_->strand_, [self = std::move(self), error] () mutable {
                if (error) self.complete(error);
                else self.complete(boost::system::error_code{
                    boost::asio::error::host_unreachable, boost::asio::error::get_system_category()});
            });
            return;
        }

        boost::asio::async_compose<Self, void (boost::system::error_code)>(
            impl::connection_connect_async{conn_, *i}, self);
    }
};

struct connection_connect_seq {
    impl::connection*       conn_;
    endpoint_resolve_result addr_; // TODO 是否可以直接使用临时对象？（延长的生命周期）

    connection_connect_seq(impl::connection* conn, const endpoint_resolve_result& eps)
    : conn_(conn)
    , addr_(eps) {}

    endpoint_resolve_result::value_type operator()() {
        auto i = addr_.begin();
        for (;;) {
            try {
                connection_connect{conn_, *i}();
            } catch(const std::exception& ex) {
                if (++i == addr_.end()) throw;
                continue;
            }
            return *i;
        }
        throw boost::system::system_error(boost::asio::error::host_unreachable,
            boost::asio::error::get_system_category());
    }
};


} // namespace detail
} // namespace quic

#endif // QUIC_DETAIL_CONNECT_H
