#ifndef QUIC_DETAIL_ATTACHED_H
#define QUIC_DETAIL_ATTACHED_H
#include "../detail/ssl.hpp"
#include "server.hpp"
#include <variant>
#include <utility>

namespace quic {
namespace impl {

struct handler {
    using handler_impl = std::variant<impl::server>;

    static void handler_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
        int idx, long argl, void *argp) {

        if (!ptr) return;
        delete reinterpret_cast<handler_impl*>(ptr);
    }

    static int handler_index() {
        static int idx = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, handler_free);
        return idx;
    }

    template <class T, class ...Args>
    T* emplace(SSL* handle, Args&&... args) {
        handler_impl* x = new handler_impl(std::in_place_type_t<T>{}, std::forward<Args>(args)...);
        SSL_set_ex_data(handle, handler_index(), x);
        return &std::get<T>(*x);
    }

};

} // namespace impl
} // namespace quic

#endif // QUIC_DETAIL_ATTACHED_H
