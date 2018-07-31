#include <evt/history_plugin/history_plugin.hpp>

#include <bsoncxx/builder/basic/document.hpp>
#include <bsoncxx/builder/basic/kvp.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/builder/stream/array.hpp>
#include <bsoncxx/json.hpp>

#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/database.hpp>
#include <mongocxx/pipeline.hpp>
#include <mongocxx/exception/query_exception.hpp>

#include <fc/io/json.hpp>
#include <fc/variant.hpp>
#include <fc/variant_object.hpp>

#include <evt/chain/contracts/evt_contract.hpp>

namespace evt {

static appbase::abstract_plugin& _history_plugin = app().register_plugin<history_plugin>();

using namespace evt;
using namespace evt::chain;
using std::string;
using std::vector;
using fc::flat_set;
using fc::variant;
using fc::optional;
using bsoncxx::builder::stream::document;

class history_plugin_impl {
public:
    const string blocks_col        = "Blocks";
    const string trans_col         = "Transactions";
    const string actions_col       = "Actions";
    const string action_traces_col = "ActionTraces";
    const string domains_col       = "Domains";
    const string tokens_col        = "Tokens";
    const string groups_col        = "Groups";
    const string fungibles_col     = "Fungibles";

public:
    history_plugin_impl()
        : chain_(app().get_plugin<chain_plugin>().chain())
        , evt_abi_(contracts::evt_contract_abi()) {
        auto& uri = app().get_plugin<mongo_db_plugin>().uri();
        
        client_ = mongocxx::client(uri);
        if(uri.database().empty()) {
            db_ = client_["EVT"];
        }
        else {
            db_ = client_[uri.database()];
        }
    }

public:
    variant get_tokens_by_public_keys(const vector<public_key_type>& pkeys);
    flat_set<string> get_domains_by_public_keys(const vector<public_key_type>& pkeys);
    flat_set<string> get_groups_by_public_keys(const vector<public_key_type>& pkeys);

    variant get_actions(const domain_name&             domain,
                        const optional<domain_key>&    key,
                        const std::vector<action_name> names,
                        const optional<int>            skip,
                        const optional<int>            take);
    variant get_transaction(const transaction_id_type& trx_id);
    variant get_transactions(const vector<public_key_type>& pkeys, const optional<int> skip, const optional<int> take);

private:
    block_id_type get_block_id_by_trx_id(const transaction_id_type& trx_id);
    string get_bson_string_value(const mongocxx::cursor::iterator& it, const std::string& key);
    string get_date_string_value(const mongocxx::cursor::iterator& it, const std::string& key);
    variant transaction_to_variant(const packed_transaction& ptrx);

public:
    mongocxx::client   client_;
    mongocxx::database db_;
    
    const controller& chain_;
    const abi_serializer evt_abi_;
};

string
history_plugin_impl::get_bson_string_value(const mongocxx::cursor::iterator& it, const std::string& key) {
    auto v = (bsoncxx::stdx::string_view)(*it)[key].get_utf8();
    return string(v.data(), v.size());
}

string
history_plugin_impl::get_date_string_value(const mongocxx::cursor::iterator& it, const std::string& key) {
    auto date = (*it)[key].get_date();
    auto tp = fc::time_point(fc::milliseconds(date.to_int64()));
    return (std::string)tp;
}

fc::variant
history_plugin_impl::transaction_to_variant(const packed_transaction& ptrx) {
    auto resolver = [this] {
        return evt_abi_;
    };

    fc::variant pretty_output;
    abi_serializer::to_variant(ptrx, pretty_output, resolver);
    return pretty_output;
}


variant
history_plugin_impl::get_tokens_by_public_keys(const vector<public_key_type>& pkeys) {
    auto results = fc::mutable_variant_object();

    auto tokens = db_[tokens_col];
    for(auto& pkey : pkeys) {
        using bsoncxx::builder::stream::document;
        document find{};
        find << "owner" << (string)pkey;
        auto cursor = tokens.find(find.view());
        try {
            for(auto it = cursor.begin(); it != cursor.end(); it++) {
                auto domain = get_bson_string_value(it, "domain");
                auto name = get_bson_string_value(it, "name");

                if(results.find(domain) == results.end()) {
                    results.set(domain, fc::variants());
                }
                results[domain].get_array().emplace_back(std::move(name));
            }
        }
        catch(mongocxx::query_exception e) {
            continue;
        }
    }
    return results;
}

flat_set<string>
history_plugin_impl::get_domains_by_public_keys(const vector<public_key_type>& pkeys) {
    flat_set<string> results;

    auto domains = db_[domains_col];
    for(auto& pkey : pkeys) {
        using bsoncxx::builder::stream::document;
        document find{};
        find << "creator" << (string)pkey;
        auto cursor = domains.find(find.view());
        try {
            for(auto it = cursor.begin(); it != cursor.end(); it++) {
                auto name = get_bson_string_value(it, "name");
                results.insert(string(name.data(), name.size()));
            }
        }
        catch(mongocxx::query_exception e) {
            continue;
        }
    }
    return results;
}

flat_set<string>
history_plugin_impl::get_groups_by_public_keys(const vector<public_key_type>& pkeys) {
    flat_set<string> results;

    auto groups = db_[groups_col];
    for(auto& pkey : pkeys) {
        document find{};
        find << "def.key" << (string)pkey;
        auto cursor = groups.find(find.view());
        try {
            for(auto it = cursor.begin(); it != cursor.end(); it++) {
                auto name = get_bson_string_value(it, "name");
                results.insert(string(name.data(), name.size()));
            }
        }
        catch(mongocxx::query_exception e) {
            continue;
        }
    }
    return results;
}

variant
history_plugin_impl::get_actions(const domain_name&             domain,
                                 const optional<domain_key>&    key,
                                 const std::vector<action_name> names,
                                 const optional<int>            skip,
                                 const optional<int>            take) {
    using namespace bsoncxx::types;
    using namespace bsoncxx::builder;
    using namespace bsoncxx::builder::stream;

    fc::variants result;

    int s = 0, t = 10;
    if(skip.valid()) {
        s = *skip;
    }
    if(take.valid()) {
        t = *take;
    }

    document match{};
    match << "domain" << (string)domain;
    if(key.valid()) {
        match << "key" << (string)*key;
    }
    if(!names.empty()) {
        array ns;
        for(auto& name : names) {
            ns << (std::string)name;
        }
        match << "name" << open_document << "$in" << ns << close_document;
    }

    document sort{};
    sort << "_id" << -1;

    auto pipeline = mongocxx::pipeline();
    pipeline.match(match.view()).sort(sort.view()).skip(s).limit(t);

    auto actions = db_[actions_col];
    auto cursor = actions.aggregate(pipeline);
    try {
        for(auto it = cursor.begin(); it != cursor.end(); it++) {
            auto v = fc::mutable_variant_object();
            v["name"] = get_bson_string_value(it, "name");
            v["domain"] = get_bson_string_value(it, "domain");
            v["key"] = get_bson_string_value(it, "key");
            v["trx_id"] = get_bson_string_value(it, "trx_id");
            v["data"] = fc::json::from_string(bsoncxx::to_json((*it)["data"].get_document().view()));
            v["created_at"] = get_date_string_value(it, "created_at");

            result.emplace_back(std::move(v));
        }
    }
    catch(mongocxx::query_exception e) {
        return variant();
    }
    return variant(std::move(result));
}

block_id_type
history_plugin_impl::get_block_id_by_trx_id(const transaction_id_type& trx_id) {
    document find{};
    find << "trx_id" << (string)trx_id;

    auto trxs = db_[trans_col];
    auto cursor = trxs.find(find.view());
    try {
        for(auto it = cursor.begin(); it != cursor.end(); it++) {
            auto bid = get_bson_string_value(it, "block_id");
            return block_id_type(bid);
        }
    }
    catch(...) {}
    FC_THROW_EXCEPTION(unknown_transaction_exception, "Cannot find transaction");
}

variant
history_plugin_impl::get_transaction(const transaction_id_type& trx_id) {
    auto block_id = get_block_id_by_trx_id(trx_id);
    auto block = chain_.fetch_block_by_id(block_id);
    for(auto& tx : block->transactions) {
        if(tx.trx.id() == trx_id) {
            return transaction_to_variant(tx.trx);
        }
    }
    FC_THROW_EXCEPTION(unknown_transaction_exception, "Cannot find transaction");
}

variant
history_plugin_impl::get_transactions(const vector<public_key_type>& pkeys, const optional<int> skip, const optional<int> take) {
    using namespace bsoncxx::types;
    using namespace bsoncxx::builder;
    using namespace bsoncxx::builder::stream;

    int s = 0, t = 10;
    if(skip.valid()) {
        s = *skip;
    }
    if(take.valid()) {
        t = *take;
    }

    document match{};
    array    keys{};

    for(auto& pkey : pkeys) {
        keys << (string)pkey;
    }
    match << "keys" << open_document << "$in" << keys << close_document;

    document sort{};
    sort << "_id" << -1;

    document project{};
    project << "trx_id" << 1;

    auto pipeline = mongocxx::pipeline();
    pipeline.match(match.view()).project(project.view()).sort(sort.view()).skip(s).limit(t);

    auto trxs = db_[trans_col];
    auto cursor = trxs.aggregate(pipeline);

    auto vars = fc::variants();
    auto tids = vector<transaction_id_type>();
    try {
        for(auto it = cursor.begin(); it != cursor.end(); it++) {
            auto tid = get_bson_string_value(it, "trx_id");
            tids.emplace_back((transaction_id_type)tid);
        }
    }
    catch(mongocxx::query_exception e) {
        return vars;
    }
    
    for(auto& tid : tids) {
        vars.emplace_back(get_transaction(tid));
    }
    return vars;
}

history_plugin::history_plugin() {}
history_plugin::~history_plugin() {}

void
history_plugin::set_program_options(options_description& cli, options_description& cfg) {
}

void
history_plugin::plugin_initialize(const variables_map& options) {
}

void
history_plugin::plugin_startup() {
    this->my_.reset(new history_plugin_impl());
}

void
history_plugin::plugin_shutdown() {
}

namespace history_apis {

fc::variant
read_only::get_tokens(const get_params& params) {
    return plugin_.my_->get_tokens_by_public_keys(params.keys);
}

fc::variant
read_only::get_domains(const get_params& params) {
    auto domains = plugin_.my_->get_domains_by_public_keys(params.keys);
    fc::variant result;
    fc::to_variant(domains, result);
    return result;
}

fc::variant
read_only::get_groups(const get_params& params) {
    auto groups = plugin_.my_->get_groups_by_public_keys(params.keys);
    fc::variant result;
    fc::to_variant(groups, result);
    return result;
}

fc::variant
read_only::get_actions(const get_actions_params& params) {
    return plugin_.my_->get_actions(params.domain, params.key, params.names, params.skip, params.take);
}

fc::variant
read_only::get_transaction(const get_transaction_params& params) {
    return plugin_.my_->get_transaction(params.id);
}

fc::variant
read_only::get_transactions(const get_transactions_params& params) {
    return plugin_.my_->get_transactions(params.keys, params.skip, params.take);
}

}  // namespace history_apis

}  // namespace evt