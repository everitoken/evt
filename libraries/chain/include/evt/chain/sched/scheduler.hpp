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


public:
    scheduler(controller& control)
        : control_(control) {}

public:
    transaction_trace_ptr push_transaction(const transaction_metadata_ptr& trx, fc::time_point deadline);

private:
    controller& control_;
};

// namespace evt::chain::sched
