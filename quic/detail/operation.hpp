#ifndef QUIC_DETAIL_OPERATION_H
#define QUIC_DETAIL_OPERATION_H


#include <boost/system/error_code.hpp>
#include <memory_resource>
#include <utility>
#include <cstdlib>
#include <iostream>

namespace quic {
namespace detail {


struct operation_base {
    enum action { unknown, destroy };
    typedef void (*func_type)(operation_base* base, action a, boost::system::error_code error);

    func_type func_; // 函数指针代替 virtual dispatch 机制

    operation_base(func_type func): func_(func) {}
    operation_base(const operation_base& op) = delete;
    operation_base(operation_base&& op) = default;
    ~operation_base() = default;

    inline void execute(action a, boost::system::error_code err = {}) {
        (*func_)(this, a, err);
    }
};


template <class Handler, class Allocator>
struct operation: operation_base {
    using allocator_type = typename std::decay<Allocator>::type;
    using handler_type = typename std::decay<Handler>::type;
    handler_type     handler_;
    allocator_type allocator_;

    operation(handler_type&& handler, allocator_type&& a)
    : operation_base(&operation::executable)
    , handler_(std::move(handler))
    , allocator_(std::move(a)) { }

    operation(const operation& op) = delete;
    operation(operation&& op) = delete;

    ~operation() = default;

    static void destroy(operation<handler_type, allocator_type>* ptr) {
        allocator_type a { std::move(ptr->allocator_) };
        ptr->~operation();
        a.deallocate(reinterpret_cast<std::byte*>(ptr), sizeof(operation<handler_type, allocator_type>));
    }

    static operation<handler_type, allocator_type>* create(handler_type&& h) {
        allocator_type a{};
        // allocator_type a = boost::asio::get_associated_allocator(socket_, std::allocator<std::byte>{});
        void* ptr = a.allocate(sizeof(operation<Handler, allocator_type>));
        return new (ptr) operation<Handler, allocator_type>(std::move(h), std::move(a));
    }

    static void executable(operation_base* base, operation_base::action action, boost::system::error_code error) {
        operation<handler_type, allocator_type>* self = static_cast<operation*>(base);
        switch (action) {
        case operation_base::action::destroy:
            operation<handler_type, allocator_type>::destroy(self);
            break;
        default:
            std::move(self->handler_)(error);
        }
    }
};


struct operation_wrapper {
    operation_base* op;
    explicit operation_wrapper(operation_base* op)
    : op(op) {
        // std::cout << "operation create1: " << this << "\n";
    }
    operation_wrapper(const operation_wrapper& o) = delete;
    operation_wrapper(operation_wrapper&& o) noexcept
    : op(std::exchange(o.op, nullptr)) {
        // std::cout << "operation create2: " << this << "\n";
    }


    operation_wrapper& operator=(const operation_wrapper& op) = delete;
    operation_wrapper& operator=(operation_wrapper&& op) = delete;
    // operation& operator=(operation&& o) noexcept {
    //     std::swap(this->op, o.op);
    //     return *this;
    // }

    void operator() (boost::system::error_code error = {}) {
        op->execute(operation_base::action::unknown, error);
    }

    ~operation_wrapper() {
        // std::cout << "operation destroy: " << this << "\n";
        if (op != nullptr) {
            op->execute(operation_base::action::destroy);
            op = nullptr;
        }
    }
};


} // namespace detail
} // namespace quic

#endif // QUIC_DETAIL_OPERATION_H
