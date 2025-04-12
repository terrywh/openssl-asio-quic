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
struct do_async_connect {
    using endpoint_type = typename connection_base<Protocol, Executor>::endpoint_type;

    connection_base<Protocol, Executor>& conn_;
    endpoint_type addr_;
    mutable enum {connecting, creating, handshaking, fail, done} state_;
    
    do_async_connect(connection_base<Protocol, Executor>& conn, const endpoint_type& addr)
    : conn_(conn)
    , addr_(addr) 
    , state_(connecting) {
       
    }

    do_async_connect(const do_async_connect& impl) = delete;
    do_async_connect(do_async_connect&& impl) = default;

    template <class Self>
    void operator ()(Self& self, boost::system::error_code error = {}) const {         
        switch (state_) {
        case connecting: {
                if (conn_.ssl_) {
                    SSL_free(conn_.ssl_);
                    conn_.ssl_ = nullptr;
                }
                state_ = creating;
                conn_.socket_.async_connect(addr_, std::move(self));
            }
            break;
        case creating:
            if (error) {
                boost::asio::post(conn_.strand_, [self = std::move(self), error] () mutable {
                    self.complete(error);
                });
                return;
            }
            BOOST_ASSERT(conn_.socket_.is_open());
            state_ = handshaking;
            conn_.create_ssl(addr_, true);
            [[fallthrough]];
        case handshaking:
            if (error) { // 链接失败，清理 SSL 上下文（作为标记）
                state_ = fail;
                boost::asio::post(conn_.strand_, [self = std::move(self), error] () mutable {
                    self.complete(error);
                });
                return;
            }
            if (int r = SSL_connect(conn_.ssl_); r != 1) {
                conn_.async_handle_error(r, std::move(self));
            } else {
                state_ = done;
                boost::asio::post(conn_.strand_, [self = std::move(self)] () mutable {
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
   
    connection_base<Protocol, Executor>& conn_;
    endpoint_seq eps_;
    mutable difference_type start_;

    do_async_connect_seq(connection_base<Protocol, Executor>& conn, const EndpointSequence& eps)
    : conn_(conn)
    , eps_(eps)
    , start_(0) {}

    do_async_connect_seq(const do_async_connect_seq& seq) = delete;
    do_async_connect_seq(do_async_connect_seq&& seq) = default;

    template <class Self>
    void operator()(Self& self, boost::system::error_code error = {}) const {
        if (conn_.ssl_ != nullptr) {
            boost::asio::post(conn_.strand_, [self = std::move(self), error] () mutable {
                self.complete(error);
            });
            return;
        }

        iterator_type i = eps_.begin();
        std::advance(i, start_++);

        if (i == eps_.end()) {
            boost::asio::post(conn_.strand_, [self = std::move(self)] () mutable {
                self.complete(boost::system::error_code{
                    boost::asio::error::host_unreachable, boost::asio::error::get_netdb_category()});
            });
            return;
        }

        static_cast<basic_connection<Protocol, Executor>&>(conn_).async_connect(*i, std::move(self));
    }
};

template <class Protocol, class Executor, class EndpointSequence>
struct do_connect_seq {
    using endpoint_seq = typename std::decay<EndpointSequence>::type;
    using endpoint_type = typename EndpointSequence::value_type;


    connection_base<Protocol, Executor>& conn_;
    EndpointSequence eps_;

    do_connect_seq(connection_base<Protocol, Executor>& conn, const EndpointSequence& eps)
    : conn_(conn)
    , eps_(eps) {}

    endpoint_type operator()() {
        for (const auto& ep : eps_) {
            static_cast<basic_connection<Protocol, Executor>&>(conn_).connect(ep);
            if (conn_.ssl_ != nullptr)
                return ep;
        }
        throw boost::system::system_error(boost::asio::error::host_unreachable, boost::asio::error::get_netdb_category());
        // boost::system::error_code{
        //     boost::asio::error::host_unreachable, boost::asio::error::get_netdb_category()});
    }
};


} // namespace detail
} // namespace quic

#endif // QUIC_DETAIL_CONNECT_H
