/**
 *  @file
 *  @copyright defined in evt/LICENSE.txt
 */
#pragma once

#include <functional>
#include <boost/noncopyable.hpp>
#include <evt/chain/controller.hpp>

namespace evt { namespace chain { namespace sched {

class scheduler : boost::noncopyable {
public:
    using push_trx_callback_func = std::function<void(transaction_trace_ptr)>;

public:
    scheduler(controller& control)
        : control_(control) {}

public:
    void push_transaction(const transaction_metadata_ptr& trx, fc::time_point deadline);

private:
    controller& control_;
};

// namespace evt::chain::sched
