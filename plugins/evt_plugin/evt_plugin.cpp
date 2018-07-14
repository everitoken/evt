/**
 *  @file
 *  @copyright defined in evt/LICENSE.txt
 */

#include <evt/evt_plugin/evt_plugin.hpp>
#include <evt/chain/types.hpp>
#include <evt/chain/asset.hpp>
#include <evt/chain/token_database.hpp>
#include <evt/chain/contracts/evt_contract.hpp>

#include <fc/container/flat.hpp>
#include <fc/io/json.hpp>
#include <fc/variant.hpp>

namespace evt {

static appbase::abstract_plugin& _evt_plugin = app().register_plugin<evt_plugin>();

using namespace evt;
using namespace evt::chain;

class evt_plugin_impl {
public:
    evt_plugin_impl(controller& db)
        : db_(db)
        , evt_abi_(contracts::evt_contract_abi()) {}

public:
    controller& db_;
    contracts::abi_serializer evt_abi_;
};

evt_plugin::evt_plugin() {}
evt_plugin::~evt_plugin() {}

void
evt_plugin::set_program_options(options_description& cli, options_description& cfg) {
}

void
evt_plugin::plugin_initialize(const variables_map& options) {
}

void
evt_plugin::plugin_startup() {
    this->my_.reset(new evt_plugin_impl(app().get_plugin<chain_plugin>().chain()));
}

void
evt_plugin::plugin_shutdown() {
}

evt_apis::read_only
evt_plugin::get_read_only_api() const {
    return evt_apis::read_only(my_->db_, my_->evt_abi_);
}

evt_apis::read_write
evt_plugin::get_read_write_api() {
    return evt_apis::read_write(my_->db_);
}

namespace evt_apis {

fc::variant
read_only::get_domain(const read_only::get_domain_params& params) {
    const auto& db = db_.token_db();
    variant    var;
    domain_def domain;
    db.read_domain(params.name, domain);
    fc::to_variant(domain, var);
    return var;
}

fc::variant
read_only::get_group(const read_only::get_group_params& params) {
    const auto& db = db_.token_db();
    variant   var;
    group_def group;
    db.read_group(params.name, group);
    fc::to_variant(group, var);
    return var;
}

fc::variant
read_only::get_token(const read_only::get_token_params& params) {
    const auto& db = db_.token_db();
    variant   var;
    token_def token;
    db.read_token(params.domain, params.name, token);
    fc::to_variant(token, var);
    return var;
}

fc::variant
read_only::get_fungible(const get_fungible_params& params) {
    const auto& db = db_.token_db();
    variant      var;
    fungible_def fungible;
    db.read_fungible(params.name, fungible);
    fc::to_variant(fungible, var);
    return var;
}

fc::variant
read_only::get_fungible_balance(const get_fungible_balance_params& params) {
    const auto& db = db_.token_db();

    if(params.sym.valid()) {
        variant var;
        asset   as;
        db.read_asset(params.address, *params.sym, as);
        fc::to_variant(as, var);
        return var;
    }
    else {
        variants vars;
        db.read_all_assets(params.address, [&vars](const auto& as) {
            variant var;
            fc::to_variant(as, var);
            vars.emplace_back(std::move(var));
            return true;
        });
        return vars;
    }
}

fc::variant
read_only::get_suspend(const get_suspend_params& params) {
    const auto& db = db_.token_db();
    variant     var;
    suspend_def suspend;
    db.read_suspend(params.name, suspend);
    abi_serializer::to_variant(suspend, var, [this]{ return evt_abi_; });
    return var;
}

}  // namespace evt_apis

}  // namespace evt
