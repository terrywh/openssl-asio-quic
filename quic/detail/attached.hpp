#ifndef QUIC_DETAIL_ATTACHED_H
#define QUIC_DETAIL_ATTACHED_H
#include "ssl.hpp"
#include <utility>

namespace quic {
namespace detail {

template <class T>
struct attached {
    using value_type = typename std::decay<T>::type;

    static void free_cb (void *parent, void *ptr, CRYPTO_EX_DATA *ad,
        int idx, long argl, void *argp) {

        if (!ptr) return;
        delete reinterpret_cast<T*>(ptr);
    }

    static int ext_idx() {
        // TODO 由于每个类型存在对应的一个 index 值，似乎存在对 ext_data 的滥用问题；
        static int idx = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, &free_cb);
        return idx;
    }

    template <class ...Args>
    T* emplace_attached(SSL* handle, Args&&... args) {
        T* x = new T(std::forward<Args>(args)...);
        SSL_set_ex_data(handle, ext_idx(), x);
        return x;
    }

    // static T* detach(SSL* ssl) {
    //     void* ptr = nullptr;
    //     int idx = ext_idx();
    //     if (ssl) {
    //         ptr = SSL_get_ex_data(ssl, idx);
    //         SSL_set_ex_data(ssl, idx, nullptr);
    //     }
    //     return reinterpret_cast<T*>(ptr);
    // }
};

} // namespace detail
} // namespace quic

#endif // QUIC_DETAIL_ATTACHED_H
