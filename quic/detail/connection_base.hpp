#ifndef QUIC_DETAIL_SOCKET_EVENT_H
#define QUIC_DETAIL_SOCKET_EVENT_H

#include "openssl.hpp"
#include "asio.hpp"
#include "../alpn.hpp"
#include "../basic_endpoint.hpp"
#include "../proto.hpp"

#include <boost/function.hpp>
#include <vector>

namespace quic {
namespace detail {

template <class Protocol, class Executor>
class connection_base {
    template <class Protocol1, class Executor1>
    friend class stream_base;
    template <class Protocol1, class Executor1>
    friend class connect_impl;
    template <class Protocol1, class Executor1>
    friend class create_stream_impl;
    template <class Protocol1, class Executor1>
    friend class accept_stream_impl;

public:
    
    using endpoint_type = basic_endpoint<Protocol>;
    using callback_type = boost::function<void (boost::system::error_code)>;

protected:
    boost::asio::ssl::context& ctx_;
    boost::asio::strand<Executor> strand_;
    boost::asio::basic_datagram_socket<Protocol, Executor> socket_;
    
    SSL* ssl_ = nullptr;

private:
    std::vector<callback_type> readable_;
    std::vector<callback_type> writable_;

protected:
    // void on_readable(callback_type cb) {


    //     boost::asio::post(strand_, [this, cb = std::move(cb)] () {
    //         readable_.emplace_back(std::move(cb));
    //         if (readable_.size() == 1) {
    //             socket_.async_wait(boost::asio::socket_base::wait_read, [this] (boost::system::error_code error) {
    //                 boost::asio::post(strand_, [this, error] () {
    //                     for (auto& callback : readable_) {
    //                         callback(error);
    //                     }
    //                     readable_.clear();
    //                 });
    //             });
    //         }
    //     });
    // }

    // void on_writable(std::function<void (boost::system::error_code)> cb) {
    //     boost::asio::post(strand_, [this, cb = std::move(cb)] () {
    //         writable_.emplace_back(std::move(cb));
    //         if (writable_.size() == 1) {
    //             socket_.async_wait(boost::asio::socket_base::wait_write, [this] (boost::system::error_code error) {
    //                 boost::asio::post(strand_, [this, error] () {
    //                     for (auto& callback : writable_) {
    //                         callback(error);
    //                     }
    //                     writable_.clear();
    //                 });
    //             });
    //         }
    //     });
    // }

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

    template <class Self>
    void handle_ssl_error(int err, Self&& self) {
        switch (err) {
        case SSL_ERROR_WANT_READ:
            this->socket_.async_wait(boost::asio::socket_base::wait_read, std::move(self));
            // socket_.on_readable(socket_type::wait_read, std::move(self));
            break;
        case SSL_ERROR_WANT_WRITE:
            this->socket_.async_wait(boost::asio::socket_base::wait_write, std::move(self));
            break;
        default:
            self.complete(boost::system::error_code{err, boost::asio::error::get_ssl_category()});
        }
    }

public:
    template <class Executor1>
    explicit connection_base(Executor1& ex, boost::asio::ssl::context& ctx, SSL* conn = nullptr)
    : ctx_(ctx)
    , strand_(ex)
    , socket_(strand_)
    , ssl_(conn) {

        if (ssl_ != nullptr) {
            int fd = SSL_get_fd(ssl_);
            BIO_sock_info_u info;
            BIO_sock_info(fd, BIO_sock_info_type::BIO_SOCK_INFO_ADDRESS, &info);
            if (BIO_ADDR_family(info.addr) == BOOST_ASIO_OS_DEF(AF_INET6)) {
                socket_ = boost::asio::basic_datagram_socket<proto>{strand_, proto::v6(), fd};
            } else {
                socket_ = boost::asio::basic_datagram_socket<proto>{strand_, proto::v4(), fd};
            }
        }
    }
    ~connection_base() {
        if (ssl_ != nullptr) SSL_free(ssl_);
    }

    boost::asio::strand<Executor>& get_executor() {
        return strand_;
    }
};

} // namespace detail
} // namespace quic

#endif // QUIC_DETAIL_SOCKET_EVENT_H
