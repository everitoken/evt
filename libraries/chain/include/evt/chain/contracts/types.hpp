/**
 *  @file
 *  @copyright defined in evt/LICENSE.txt
 */
#pragma once

#include <boost/multiprecision/cpp_dec_float.hpp>

#include <evt/chain/address.hpp>
#include <evt/chain/asset.hpp>
#include <evt/chain/percent_slim.hpp>
#include <evt/chain/chain_config.hpp>
#include <evt/chain/config.hpp>
#include <evt/chain/types.hpp>
#include <evt/chain/transaction.hpp>
#include <evt/chain/producer_schedule.hpp>

#include <evt/chain/contracts/authorizer_ref.hpp>
#include <evt/chain/contracts/group.hpp>
#include <evt/chain/contracts/metadata.hpp>
#include <evt/chain/contracts/evt_link.hpp>

namespace evt { namespace chain { namespace contracts {

#define EVT_ACTION(actname, version, acttypename)    \
    acttypename() = default;                         \
                                                     \
    static constexpr auto                            \
    get_action_name() {                              \
        return evt::chain::name(N(actname));         \
    }                                                \
                                                     \
    static std::string                               \
    get_type_name() {                                \
        return #acttypename;                         \
    }                                                \
                                                     \
    static constexpr auto                            \
    get_version() {                                  \
        return version;                              \
    }

#define EVT_ACTION_VER1(actname)              EVT_ACTION(actname, 1, actname)
#define EVT_ACTION_VER2(actname, acttypename) EVT_ACTION(actname, 2, acttypename)
#define EVT_ACTION_VER3(actname, acttypename) EVT_ACTION(actname, 3, acttypename)

using domain_name     = evt::chain::domain_name;
using domian_key      = evt::chain::domain_key;
using token_name      = evt::chain::token_name;
using permission_name = evt::chain::permission_name;
using account_name    = evt::chain::account_name;
using fungible_name   = evt::chain::fungible_name;
using symbol_name     = evt::chain::symbol_name;
using symbol_id_type  = evt::chain::symbol_id_type;
using user_id         = evt::chain::public_key_type;
using group_name      = evt::chain::group_name;
using group_key       = evt::chain::address;
using group_def       = group;
using balance_type    = evt::chain::asset;
using address_type    = evt::chain::address;
using address_list    = small_vector<address_type, 4>;
using conf_key        = evt::chain::conf_key;
using percent_type    = evt::chain::percent_type;
using percent_slim    = evt::chain::percent_slim;

// represent for property for one symbol in one account
// also records the create time
struct property {
    int64_t  amount;        // amount for asset
    symbol   sym;           // symbol
    uint32_t created_at;    // utc seconds
    uint32_t created_index; // action index at that time
};

struct token_def {
    token_def() = default;
    token_def(const domain_name& domain, const token_name& name, const address_list& owner)
        : domain(domain)
        , name(name)
        , owner(owner) {}

    domain_name  domain;
    token_name   name;
    address_list owner;

    meta_list metas;
};

struct key_weight {
    public_key_type key;
    weight_type     weight;
};

struct authorizer_weight {
    authorizer_weight() = default;
    authorizer_weight(const authorizer_ref& ref, weight_type weight)
        : ref(ref), weight(weight) {}

    authorizer_ref ref;
    weight_type    weight;
};

struct permission_def {
    permission_def() = default;

    permission_name                    name;
    uint32_t                           threshold;
    small_vector<authorizer_weight, 4> authorizers;
};

struct domain_def {
    domain_def() = default;

    domain_name    name;
    user_id        creator;
    time_point_sec create_time;

    permission_def issue;
    permission_def transfer;
    permission_def manage;

    meta_list metas;
};

// Remaining for the usage in genesis state
struct fungible_def_genesis {
    fungible_def_genesis() = default;

    fungible_name  name;
    symbol_name    sym_name;
    symbol         sym;
    
    user_id        creator;
    time_point_sec create_time;

    permission_def issue;
    permission_def manage;

    asset total_supply;
    
    meta_list metas;
};

struct fungible_def {
    fungible_def() = default;

    fungible_name  name;
    symbol_name    sym_name;
    symbol         sym;
    
    user_id        creator;
    time_point_sec create_time;

    permission_def issue;
    permission_def transfer;
    permission_def manage;

    asset total_supply;
    
    meta_list metas;
};

enum class suspend_status {
    proposed = 0, executed, failed, cancelled
};

struct suspend_def {
    suspend_def() = default;

    proposal_name                      name;
    public_key_type                    proposer;
    enum_type<uint8_t, suspend_status> status;
    transaction                        trx;
    public_keys_set                    signed_keys;
    signatures_type                    signatures;
};

enum class asset_type {
    tokens = 0, fungible, max_value = fungible
};

enum class lock_status {
    proposed = 0, succeed, failed
};

struct locknft_def {
    domain_name                 domain;
    small_vector<token_name, 4> names;
};

struct lockft_def {
    address from;
    asset   amount;
};

using lock_asset = variant_wrapper<asset_type, locknft_def, lockft_def>;

enum class lock_type {
    cond_keys = 0, max_value = cond_keys
};

struct lock_condkeys {
    uint16_t                         threshold;
    small_vector<public_key_type, 4> cond_keys;
};

using lock_condition = variant_wrapper<lock_type, lock_condkeys>;

struct lock_def {
    proposal_name                   name;
    user_id                         proposer;
    enum_type<uint8_t, lock_status> status;

    time_point_sec              unlock_time;
    time_point_sec              deadline;
    small_vector<lock_asset, 4> assets;
    
    lock_condition           condition;
    small_vector<address, 4> succeed;
    small_vector<address, 4> failed;

    public_keys_set signed_keys;
};

enum class lock_aprv_type {
    cond_key = 0, max_value = cond_key
};

using lock_aprvdata = variant_wrapper<lock_aprv_type, void_t>;

enum class dist_receiver_type {
    address = 0, ftholders, max_value = ftholders
};

struct dist_stack_receiver {
public:
    dist_stack_receiver() = default;
    dist_stack_receiver(const asset th) : threshold(th) {}

public:
    asset threshold;
};

using dist_receiver = variant_wrapper<dist_receiver_type, address, dist_stack_receiver>;

enum class dist_rule_type {
    fixed = 0, percent, remaining_percent, max_value = remaining_percent
};

struct dist_fixed_rule {
    dist_receiver receiver;
    asset         amount;
};

struct dist_percent_rule {
    dist_receiver receiver;
    percent_type  percent;
};

struct dist_rpercent_rule {
    dist_receiver receiver;
    percent_type  percent;
};

using dist_rule  = variant_wrapper<dist_rule_type, dist_fixed_rule, dist_percent_rule, dist_rpercent_rule>;
using dist_rules = small_vector<dist_rule, 4>;

struct dist_percent_rule_v2 {
    dist_receiver receiver;
    percent_slim  percent;
};

struct dist_rpercent_rule_v2 {
    dist_receiver receiver;
    percent_slim  percent;
};

using dist_rule_v2  = variant_wrapper<dist_rule_type, dist_fixed_rule, dist_percent_rule_v2, dist_rpercent_rule_v2>;
using dist_rules_v2 = small_vector<dist_rule_v2, 4>;

enum class passive_method_type {
    within_amount = 0,
    outside_amount
};

struct passive_method {
public:
    passive_method() = default;
    passive_method(name action, passive_method_type method)
        : action(action), method(method) {}

public:
    name                                    action;
    enum_type<uint8_t, passive_method_type> method;
};
using passive_methods = small_vector<passive_method, 4>;

struct passive_bonus {
    symbol_id_type  sym_id;
    percent_slim    rate;
    asset           base_charge;
    optional<asset> charge_threshold;
    optional<asset> minimum_charge;
    asset           dist_threshold;
    dist_rules_v2   rules;
    passive_methods methods;   // without actions specify here, others will be `within` defaultly
    uint32_t        round;
    time_point      deadline;  // deadline for latest round
};

struct passive_bonus_slim {
    symbol_id_type    sym_id;
    percent_slim      rate;
    int64_t           base_charge;
    optional<int64_t> charge_threshold;
    optional<int64_t> minimum_charge;
    passive_methods   methods;
};

struct newdomain {
    domain_name name;
    user_id     creator;

    permission_def issue;
    permission_def transfer;
    permission_def manage;

    EVT_ACTION_VER1(newdomain);
};

struct issuetoken {
    domain_name                 domain;
    small_vector<token_name, 4> names;
    address_list                owner;

    EVT_ACTION_VER1(issuetoken);
};

struct transfer {
    domain_name  domain;
    token_name   name;
    address_list to;
    string       memo;

    EVT_ACTION_VER1(transfer);
};

struct destroytoken {
    domain_name domain;
    token_name  name;

    EVT_ACTION_VER1(destroytoken);
};

struct newgroup {
    group_name name;
    group_def  group;

    EVT_ACTION_VER1(newgroup);
};

struct updategroup {
    group_name name;
    group_def  group;

    EVT_ACTION_VER1(updategroup);
};

struct updatedomain {
    domain_name name;

    optional<permission_def> issue;
    optional<permission_def> transfer;
    optional<permission_def> manage;

    EVT_ACTION_VER1(updatedomain);
};

struct newfungible {
    fungible_name name;
    symbol_name   sym_name;
    symbol        sym;
    user_id       creator;

    permission_def issue;
    permission_def manage;

    asset total_supply;

    EVT_ACTION_VER1(newfungible);
};

struct newfungible_v2 {
    fungible_name name;
    symbol_name   sym_name;
    symbol        sym;
    user_id       creator;

    permission_def issue;
    permission_def transfer;
    permission_def manage;

    asset total_supply;

    EVT_ACTION_VER2(newfungible, newfungible_v2);
};

struct updfungible {
    symbol_id_type sym_id;

    optional<permission_def> issue;
    optional<permission_def> manage;

    EVT_ACTION_VER1(updfungible);
};

struct updfungible_v2 {
    symbol_id_type sym_id;

    optional<permission_def> issue;
    optional<permission_def> transfer;
    optional<permission_def> manage;

    EVT_ACTION_VER2(updfungible, updfungible_v2);
};

struct issuefungible {
    address_type address;
    asset        number;
    string       memo;

    EVT_ACTION_VER1(issuefungible);
};

struct transferft {
    address_type from;
    address_type to;
    asset        number;
    string       memo;

    EVT_ACTION_VER1(transferft);
};

struct recycleft {
    address_type address;
    asset        number;
    string       memo;

    EVT_ACTION_VER1(recycleft);
};

struct destroyft {
    address_type address;
    asset        number;
    string       memo;

    EVT_ACTION_VER1(destroyft);
};

struct evt2pevt {
    address_type from;
    address_type to;
    asset        number;
    string       memo;

    EVT_ACTION_VER1(evt2pevt);
};

struct addmeta {
    meta_key       key;
    meta_value     value;
    authorizer_ref creator;

    EVT_ACTION_VER1(addmeta);
};

struct newsuspend {
    proposal_name name;
    user_id       proposer;
    transaction   trx;

    EVT_ACTION_VER1(newsuspend);
};

struct cancelsuspend {
    proposal_name name;

    EVT_ACTION_VER1(cancelsuspend);
};

struct aprvsuspend {
    proposal_name                   name;
    small_vector<signature_type, 4> signatures;

    EVT_ACTION_VER1(aprvsuspend);
};

struct execsuspend {
    proposal_name name;
    user_id       executor;

    EVT_ACTION_VER1(execsuspend);
};

struct paycharge {
    address  payer;
    uint32_t charge;

    EVT_ACTION_VER1(paycharge);
};

struct paybonus {
    address payer;
    asset   amount;

    EVT_ACTION_VER1(paybonus);
};

struct everipass {
    evt_link link;

    EVT_ACTION_VER1(everipass);
};

struct everipass_v2 {
    evt_link         link;
    optional<string> memo;

    EVT_ACTION_VER2(everipass, everipass_v2);
};

struct everipay {
    evt_link link;
    address  payee;
    asset    number;

    EVT_ACTION_VER1(everipay);
};

struct everipay_v2 {
    evt_link         link;
    address          payee;
    asset            number;
    optional<string> memo;

    EVT_ACTION_VER2(everipay, everipay_v2);
};

struct prodvote {
    account_name producer;
    conf_key     key;
    int64_t      value;

    EVT_ACTION_VER1(prodvote);
};

struct updsched {
    vector<producer_key> producers;

    EVT_ACTION_VER1(updsched);
};

struct newlock {
    proposal_name name;
    user_id       proposer;

    time_point_sec              unlock_time;
    time_point_sec              deadline;
    small_vector<lock_asset, 4> assets;
    
    lock_condition           condition;
    small_vector<address, 4> succeed;
    small_vector<address, 4> failed;

    EVT_ACTION_VER1(newlock);
};

struct aprvlock {
    proposal_name name;
    user_id       approver;
    lock_aprvdata data;

    EVT_ACTION_VER1(aprvlock);
};

struct tryunlock {
    proposal_name name;
    user_id       executor;

    EVT_ACTION_VER1(tryunlock);
};

struct setpsvbonus {
    symbol          sym;
    percent_type    rate;
    asset           base_charge;
    optional<asset> charge_threshold;
    optional<asset> minimum_charge;
    asset           dist_threshold;
    dist_rules      rules;
    passive_methods methods;

    EVT_ACTION_VER1(setpsvbonus);
};

struct setpsvbonus_v2 {
    symbol_id_type  sym_id;
    percent_slim    rate;
    asset           base_charge;
    optional<asset> charge_threshold;
    optional<asset> minimum_charge;
    asset           dist_threshold;
    dist_rules_v2   rules;
    passive_methods methods;

    EVT_ACTION_VER2(setpsvbonus, setpsvbonus_v2);
};

struct distpsvbonus {
    symbol_id_type    sym_id;
    time_point        deadline;
    optional<address> final_receiver;

    EVT_ACTION_VER1(distpsvbonus);
};

struct recvpsvbonus {
    symbol_id_type                   sym_id;
    small_vector<public_key_type, 2> receivers;
    uint32_t                         rule_index;
};

}}}  // namespace evt::chain::contracts

FC_REFLECT(evt::chain::contracts::property, (amount)(sym)(created_at)(created_index));
FC_REFLECT(evt::chain::contracts::token_def, (domain)(name)(owner)(metas));
FC_REFLECT(evt::chain::contracts::key_weight, (key)(weight));
FC_REFLECT(evt::chain::contracts::authorizer_weight, (ref)(weight));
FC_REFLECT(evt::chain::contracts::permission_def, (name)(threshold)(authorizers));
FC_REFLECT(evt::chain::contracts::domain_def, (name)(creator)(create_time)(issue)(transfer)(manage)(metas));
FC_REFLECT(evt::chain::contracts::fungible_def_genesis, (name)(sym_name)(sym)(creator)(create_time)(issue)(manage)(total_supply)(metas));
FC_REFLECT(evt::chain::contracts::fungible_def, (name)(sym_name)(sym)(creator)(create_time)(issue)(transfer)(manage)(total_supply)(metas));

FC_REFLECT_ENUM(evt::chain::contracts::suspend_status, (proposed)(executed)(failed)(cancelled));
FC_REFLECT(evt::chain::contracts::suspend_def, (name)(proposer)(status)(trx)(signed_keys)(signatures));

FC_REFLECT_ENUM(evt::chain::contracts::asset_type, (tokens)(fungible));
FC_REFLECT_ENUM(evt::chain::contracts::lock_status, (proposed)(succeed)(failed));
FC_REFLECT(evt::chain::contracts::locknft_def, (domain)(names));
FC_REFLECT(evt::chain::contracts::lockft_def, (from)(amount));
FC_REFLECT_ENUM(evt::chain::contracts::lock_type, (cond_keys));
FC_REFLECT(evt::chain::contracts::lock_condkeys, (threshold)(cond_keys));
FC_REFLECT(evt::chain::contracts::lock_def, (name)(proposer)(status)(unlock_time)(deadline)(assets)(condition)(succeed)(failed)(signed_keys));
FC_REFLECT_ENUM(evt::chain::contracts::lock_aprv_type, (cond_key));

FC_REFLECT_ENUM(evt::chain::contracts::dist_receiver_type, (address)(ftholders));
FC_REFLECT(evt::chain::contracts::dist_stack_receiver, (threshold));
FC_REFLECT_ENUM(evt::chain::contracts::dist_rule_type, (fixed)(percent)(remaining_percent));
FC_REFLECT(evt::chain::contracts::dist_fixed_rule, (receiver)(amount));
FC_REFLECT(evt::chain::contracts::dist_percent_rule, (receiver)(percent));
FC_REFLECT(evt::chain::contracts::dist_rpercent_rule, (receiver)(percent));
FC_REFLECT(evt::chain::contracts::dist_percent_rule_v2, (receiver)(percent));
FC_REFLECT(evt::chain::contracts::dist_rpercent_rule_v2, (receiver)(percent));
FC_REFLECT_ENUM(evt::chain::contracts::passive_method_type, (within_amount)(outside_amount));
FC_REFLECT(evt::chain::contracts::passive_method, (action)(method));
FC_REFLECT(evt::chain::contracts::passive_bonus, (sym_id)(rate)(base_charge)(charge_threshold)(minimum_charge)(dist_threshold)(rules)(methods)(round)(deadline));
FC_REFLECT(evt::chain::contracts::passive_bonus_slim, (sym_id)(rate)(base_charge)(charge_threshold)(minimum_charge)(methods));

FC_REFLECT(evt::chain::contracts::newdomain, (name)(creator)(issue)(transfer)(manage));
FC_REFLECT(evt::chain::contracts::issuetoken, (domain)(names)(owner));
FC_REFLECT(evt::chain::contracts::transfer, (domain)(name)(to)(memo));
FC_REFLECT(evt::chain::contracts::destroytoken, (domain)(name));
FC_REFLECT(evt::chain::contracts::newgroup, (name)(group));
FC_REFLECT(evt::chain::contracts::updategroup, (name)(group));
FC_REFLECT(evt::chain::contracts::updatedomain, (name)(issue)(transfer)(manage));
FC_REFLECT(evt::chain::contracts::newfungible, (name)(sym_name)(sym)(creator)(issue)(manage)(total_supply));
FC_REFLECT(evt::chain::contracts::newfungible_v2, (name)(sym_name)(sym)(creator)(issue)(transfer)(manage)(total_supply));
FC_REFLECT(evt::chain::contracts::updfungible, (sym_id)(issue)(manage));
FC_REFLECT(evt::chain::contracts::updfungible_v2, (sym_id)(issue)(transfer)(manage));
FC_REFLECT(evt::chain::contracts::issuefungible, (address)(number)(memo));
FC_REFLECT(evt::chain::contracts::transferft, (from)(to)(number)(memo));
FC_REFLECT(evt::chain::contracts::recycleft, (address)(number)(memo));
FC_REFLECT(evt::chain::contracts::destroyft, (address)(number)(memo));
FC_REFLECT(evt::chain::contracts::evt2pevt, (from)(to)(number)(memo));
FC_REFLECT(evt::chain::contracts::addmeta, (key)(value)(creator));
FC_REFLECT(evt::chain::contracts::newsuspend, (name)(proposer)(trx));
FC_REFLECT(evt::chain::contracts::cancelsuspend, (name));
FC_REFLECT(evt::chain::contracts::aprvsuspend, (name)(signatures));
FC_REFLECT(evt::chain::contracts::execsuspend, (name)(executor));
FC_REFLECT(evt::chain::contracts::paycharge, (payer)(charge));
FC_REFLECT(evt::chain::contracts::paybonus, (payer)(amount));
FC_REFLECT(evt::chain::contracts::everipass, (link));
FC_REFLECT(evt::chain::contracts::everipass_v2, (link)(memo));
FC_REFLECT(evt::chain::contracts::everipay, (link)(payee)(number));
FC_REFLECT(evt::chain::contracts::everipay_v2, (link)(payee)(number)(memo));
FC_REFLECT(evt::chain::contracts::prodvote, (producer)(key)(value));
FC_REFLECT(evt::chain::contracts::updsched, (producers));
FC_REFLECT(evt::chain::contracts::newlock, (name)(proposer)(unlock_time)(deadline)(assets)(condition)(succeed)(failed));
FC_REFLECT(evt::chain::contracts::aprvlock, (name)(approver)(data));
FC_REFLECT(evt::chain::contracts::tryunlock, (name)(executor));
FC_REFLECT(evt::chain::contracts::setpsvbonus, (sym)(rate)(base_charge)(charge_threshold)(minimum_charge)(dist_threshold)(rules)(methods));
FC_REFLECT(evt::chain::contracts::setpsvbonus_v2, (sym_id)(rate)(base_charge)(charge_threshold)(minimum_charge)(dist_threshold)(rules)(methods));
FC_REFLECT(evt::chain::contracts::distpsvbonus, (sym_id)(deadline)(final_receiver));
