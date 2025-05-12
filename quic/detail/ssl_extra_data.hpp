#ifndef QUIC_DETAIL_ATTACHED_H
#define QUIC_DETAIL_ATTACHED_H
#include "../detail/ssl.hpp"
#include "../impl/connection.hpp"
#include "../impl/stream.hpp"
#include "../impl/server.hpp"
#include <variant>

namespace quic {
namespace detail {

    struct ssl_extra_data {
        using variant_object = std::variant<impl::server, impl::connection, impl::stream>;

        static void handler_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
            int idx, long argl, void *argp) {

            if (!ptr) return;
            delete reinterpret_cast<variant_object*>(ptr);
        }
        static int handler_index() {
            static int idx = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, handler_free);
            return idx;
        }
        template <class Impl, class ...Args>
        static Impl* emplace(SSL* handle, Args&&... args) {
            variant_object* x = new variant_object(std::in_place_type_t<Impl>{}, handle, std::forward<Args>(args)...);
            if (handle) SSL_set_ex_data(handle, handler_index(), x);
            return &std::get<Impl>(*x);
        }
        template <class Impl>
        static Impl* get(SSL* handle) {
            variant_object* x = reinterpret_cast<variant_object*>(SSL_get_ex_data(handle, handler_index()));
            return &std::get<Impl>(*x);
        }
        template <class Impl>
        static void set(SSL* handle, Impl* x) {
            if (handle) SSL_set_ex_data(handle, handler_index(), x);
        }
    };

} // namespace detail
} // namespace quic

#endif // QUIC_DETAIL_ATTACHED_H
