#ifndef QUIC_IMPL_ERROR_HANDLER_H
#define QUIC_IMPL_ERROR_HANDLER_H

#include "../detail/ssl.hpp"
#include <boost/asio/error.hpp>
#include <boost/asio/ssl/error.hpp>

namespace quic {
namespace detail {

    class error_handler {
        int error_;
    public:
        error_handler(int error)
        : error_(error) {}

        [[noreturn]] void throws() {
            switch (error_) {
            case SSL_ERROR_SYSCALL:
                throw boost::system::system_error{errno, boost::asio::error::get_system_category()};
                break;
            case SSL_ERROR_SSL:
                error_ = ERR_get_error();
                [[fallthrough]];
            default:
                throw boost::system::system_error{error_, boost::asio::error::get_ssl_category()};
            }
        }

        template <class Self>
        bool returns(Self& self) {
            switch (error_) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                return true;
            case SSL_ERROR_ZERO_RETURN:
                self.complete(boost::system::error_code{SSL_R_STREAM_FINISHED, boost::asio::error::get_ssl_category()}, read_);
                return false;
            case SSL_ERROR_SYSCALL:
                self.complete(boost::system::error_code{errno, boost::asio::error::get_system_category()}, wrote_);
                return false;
            case SSL_ERROR_SSL:
                error_ = ERR_get_error();
                [[fallthrough]];
            default:
                self.complete(boost::system::error_code{error_, boost::asio::error::get_ssl_category()}, wrote_);
                return false;
            }
        }
    };


} // namespace detail
} // namespace quic


#endif // QUIC_IMPL_ERROR_HANDLER_H
