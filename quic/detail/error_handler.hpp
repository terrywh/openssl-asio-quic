#ifndef QUIC_IMPL_ERROR_HANDLER_H
#define QUIC_IMPL_ERROR_HANDLER_H

#include "../detail/ssl.hpp"
#include <boost/asio/error.hpp>
#include <boost/asio/ssl/error.hpp>

namespace quic {
namespace detail {

    class error_handler {
        int error_;
        // 确认 SSL 错误类型（来自 boost/asio/ssl/impl/context.ipp 文件）
        static inline boost::system::error_code translate_error(long error) {
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
            if (ERR_SYSTEM_ERROR(error))
            {
                return boost::system::error_code(
                    static_cast<int>(ERR_GET_REASON(error)),
                    boost::asio::error::get_system_category());
            }
#endif // (OPENSSL_VERSION_NUMBER >= 0x30000000L)

            return boost::system::error_code(static_cast<int>(error),
                boost::asio::error::get_ssl_category());
        }
    public:
        error_handler(int error)
        : error_(error) {}

        [[noreturn]] void throws() {
            switch (error_) {
            case SSL_ERROR_SYSCALL:
                throw boost::system::system_error{errno, boost::asio::error::get_system_category()};
                // break;
            case SSL_ERROR_SSL:
                throw boost::system::system_error{translate_error(ERR_get_error())};
                // break;
            default:
                throw boost::system::system_error{error_, boost::asio::error::get_ssl_category()};
            }
        }

        template <class Self>
        bool wait(Self& self) {
            switch (error_) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                return true;
            case SSL_ERROR_ZERO_RETURN:
                self.complete(boost::system::error_code{SSL_R_STREAM_FINISHED, boost::asio::error::get_ssl_category()});
                return false;
            case SSL_ERROR_SYSCALL:
                self.complete(boost::system::error_code{errno, boost::asio::error::get_system_category()});
                return false;
            case SSL_ERROR_SSL:
                self.complete(translate_error(ERR_get_error()));
                ERR_print_errors_fp(stderr);
                return false;
            default:
                self.complete(boost::system::error_code{static_cast<int>(error_), boost::asio::error::get_ssl_category()});
                return false;
            }
        }

        template <class Self>
        bool wait_ex(Self& self, std::size_t size = 0) {
            switch (error_) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                return true;
            case SSL_ERROR_ZERO_RETURN:
                self.complete(boost::system::error_code{SSL_R_STREAM_FINISHED, boost::asio::error::get_ssl_category()}, size);
                return false;
            case SSL_ERROR_SYSCALL:
                self.complete(boost::system::error_code{errno, boost::asio::error::get_system_category()}, size);
                return false;
            case SSL_ERROR_SSL:
                self.complete(translate_error(ERR_get_error()), size);
                return false;
            default:
                self.complete(boost::system::error_code{error_, boost::asio::error::get_ssl_category()}, size);
                return false;
            }
        }
    };


} // namespace detail
} // namespace quic


#endif // QUIC_IMPL_ERROR_HANDLER_H
