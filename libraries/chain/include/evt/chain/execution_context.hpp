/**
 *  @file
 *  @copyright defined in evt/LICENSE.txt
 */
#pragma once

#include <boost/noncopyable.hpp>
#include <evt/chain/exceptions.hpp>
#include <evt/chain/types.hpp>
#include <evt/chain/contracts/types.hpp>

namespace evt { namespace chain {

struct action_ver {
    name   act;
    int    ver;
    string type;
};

class execution_context : boost::noncopyable {
public:
    virtual ~execution_context() {}

    virtual int index_of(name act) const = 0;
    virtual std::string get_acttype_name(name act) const = 0;
    virtual int set_version(name act, int ver) = 0;
    virtual int set_version_unsafe(name act, int ver) = 0;
    virtual int get_current_version(name act) const = 0;
    virtual int get_max_version(name act) const = 0;
    virtual std::vector<action_ver> get_current_actions() const = 0;

public:
    void set_versions(const std::vector<action_ver>& acts);
};

// helper method to add const lvalue reference to type object
template<typename T>
using add_clr_t = typename std::add_const<typename std::add_lvalue_reference<T>::type>::type;

}}  // namespace evt::chain

FC_REFLECT(evt::chain::action_ver, (act)(ver)(type));