/**
 *  @file
 *  @copyright defined in evt/LICENSE.txt
 */

#include <iostream>
#include <limits>
#include <regex>
#include <string>
#include <type_traits>
#include <vector>

#include <pwd.h>
#include <unistd.h>

#pragma push_macro("N")
#undef N

#include <boost/asio/local/stream_protocol.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
#include <boost/filesystem.hpp>
// #include <boost/process.hpp>
#include <boost/range/algorithm/find_if.hpp>
#include <boost/range/algorithm/sort.hpp>
#include <boost/range/algorithm/copy.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>

#pragma pop_macro("N")

#include <fc/exception/exception.hpp>
#include <fc/io/console.hpp>
#include <fc/io/fstream.hpp>
#include <fc/io/json.hpp>
#include <fc/variant.hpp>

#include <evt/chain/config.hpp>
#include <evt/chain/exceptions.hpp>
#include <evt/chain/execution_context_mock.hpp>
#include <evt/chain/contracts/types.hpp>
#include <evt/chain/contracts/abi_serializer.hpp>
#include <evt/chain/contracts/evt_contract_abi.hpp>
#include <evt/chain_plugin/chain_plugin.hpp>
#include <evt/utilities/key_conversion.hpp>

#include "CLI11.hpp"
#include "config.hpp"
#include "help_text.hpp"
#include "httpc.hpp"
#include "localize.hpp"

using namespace std;
using namespace evt;
using namespace evt::chain;
using namespace evt::chain::contracts;
using namespace evt::utilities;
using namespace evt::client::help;
using namespace evt::client::http;
using namespace evt::client::localize;
using namespace evt::client::config;
using namespace boost::filesystem;

FC_DECLARE_EXCEPTION(explained_exception, 9000000, "explained exception, see error log");
FC_DECLARE_EXCEPTION(localized_exception, 10000000, "an error occured");

#define EVTC_ASSERT(TEST, ...)                                \
    FC_EXPAND_MACRO(                                          \
        FC_MULTILINE_MACRO_BEGIN if(UNLIKELY(!(TEST))) {      \
            std::cerr << localized(__VA_ARGS__) << std::endl; \
            FC_THROW_EXCEPTION(explained_exception, #TEST);   \
        } FC_MULTILINE_MACRO_END)

bfs::path
determine_home_directory() {
    bfs::path      home;
    struct passwd* pwd = getpwuid(getuid());
    if(pwd) {
        home = pwd->pw_dir;
    }
    else {
        home = getenv("HOME");
    }
    if(home.empty())
        home = "./";
    return home;
}

string program            = "evtc";
string url                = "http://127.0.0.1:8888";
string default_wallet_url = "unix://" + fc::path(determine_home_directory() / "evt-wallet/evtwd.sock").to_native_ansi_path();
string wallet_url; //to be set to default_wallet_url in main

bool no_verify = false;
vector<string> headers;

auto   tx_expiration = fc::seconds(30);
string tx_ref_block_num_or_id;
bool   tx_dont_broadcast = false;
bool   tx_skip_sign      = false;
bool   tx_print_json     = false;
bool   print_request     = false;
bool   print_response    = false;
bool   get_charge_only   = false;

string   propname;
string   proposer;
string   payer;
uint32_t max_charge = 10000;

void
print_info(const fc::variant& info, int indent = 0) {
    try {
        if(info.is_object()) {
            for(auto& obj : info.get_object()) {
                for(int i = 0; i < indent; i++) {
                    cerr << "    ";
                }
                cerr << "|";
                cerr << "->";
                cerr << obj.key() << " : ";
                if(obj.value().is_object()) {
                    cerr << endl;
                    print_info(obj.value(), indent + 1);
                }
                else if(obj.value().is_array()) {
                    if(obj.value().get_array().size() == 0) {
                        cerr << "(empty)" << endl;
                        continue;
                    }
                    cerr << endl;
                    print_info(obj.value(), indent + 1);
                }
                else {
                    cerr << obj.value().as_string() << endl;
                }
            }
        }
        else if(info.is_array()) {
            auto& arr  = info.get_array();
            auto  size = arr.size();

            auto i = 1;
            for(auto& a : arr) {
                if(indent == 0) {
                    cerr << "(" << i << " of " << size << ")" << endl;
                }
                print_info(a, indent);
                i++;
            }
        }
        else {
            for(int i = 0; i < indent; i++) {
                cerr << "      ";
            }
            cerr << "|";
            cerr << "->";
            cerr << info.as_string() << endl;
        }
    }
    FC_CAPTURE_AND_RETHROW((info))
}

void
print_action(const fc::variant& at) {
    const auto& act     = at["act"].get_object();
    auto        func    = act["name"].as_string();
    auto        args    = act["data"];
    auto        console = at["console"].as_string();

    std::cout << "   action : " << func << std::endl;
    std::cout << "   domain : " << act["domain"].as_string() << std::endl;
    std::cout << "      key : " << act["key"].as_string() << std::endl;
    std::cout << "  elapsed : " << at["elapsed"].as_string() << " " << "us" << std::endl;
    std::cout << "  details : " << std::endl;
    print_info(args);

    if(console.size()) {
        std::stringstream ss(console);
        string            line;
        std::getline(ss, line);
        std::cout << ">> " << line << "\n";
    }
}

void
print_result(const fc::variant& result) {
    try {
        if(result.is_object() && result.get_object().contains("processed")) {
            const auto& processed      = result["processed"];
            const auto& transaction_id = processed["id"].as_string();
            string      status         = processed["receipt"].is_object()
                                ? processed["receipt"]["status"].as_string()
                                : "failed";
            cerr << status << " transaction: " << transaction_id << std::endl;
            cerr << "total elapsed: " << processed["elapsed"].as_string() << " us" << std::endl;

            cerr << "total charge: " << asset(processed["charge"].as_int64(), evt_sym()) << std::endl;

            if(status == "failed") {
                auto soft_except = processed["except"].as<std::optional<fc::exception>>();
                if(soft_except) {
                    edump((soft_except->to_detail_string()));
                }
            }
            else {
                const auto& actions = processed["action_traces"].get_array();

                auto i    = 1;
                auto size = actions.size();
                
                for(const auto& a : actions) {
                    cerr << "(" << i << " of " << size << ")" << endl;
                    print_action(a);
                    i++;
                }
                wlog("\rwarning: transaction executed locally, but may not be "
                     "confirmed by the network yet");
            }
        }
        else {
            cerr << fc::json::to_pretty_string(result) << endl;
        }
    }
    FC_CAPTURE_AND_RETHROW((result))
}

fc::microseconds
parse_time_span_str(const string& str) {
    auto t = std::stoul(str.substr(0, str.size() - 1));
    auto s = str.substr(str.size() - 1);

    if(s == "s") {
        return fc::seconds(t);
    }
    else if(s == "m") {
        return fc::minutes(t);
    }
    else if(s == "h") {
        return fc::hours(t);
    }
    else if(s == "d") {
        return fc::days(t);
    }
    else {
        FC_ASSERT(false, "Not support time: ${t}", ("t",str));
    }
}

evt::client::http::http_context context;

void
add_standard_transaction_options(CLI::App* cmd) {
    CLI::callback_t parse_expiration = [](CLI::results_t res) -> bool {
        if(res.size() == 0) {
            return false;
        }

        tx_expiration = parse_time_span_str(res[0]);
        return true;
    };

    cmd->add_option("-x,--expiration", parse_expiration, localized("Set the time string('1s','2m','3h','4d') before a transaction expires, defaults to 30s"));
    cmd->add_flag("-s,--skip-sign", tx_skip_sign, localized("Specify if unlocked wallet keys should be used to sign transaction"));
    cmd->add_flag("-d,--dont-broadcast", tx_dont_broadcast, localized("Don't broadcast transaction to the network (just print to stdout)"));
    cmd->add_option("-r,--ref-block", tx_ref_block_num_or_id, localized("Set the reference block num or block id used for TAPOS (Transaction as Proof-of-Stake)"));
    cmd->add_option("-p,--payer", payer, localized("Payer address to be billed for this transaction"))->required();
    cmd->add_option("-c,--max-charge", max_charge, localized("Max charge to be payed for this transaction"));
    cmd->add_flag("-g,--get-charge", get_charge_only, localized("Get charge of one transaction instead pushing"));

    auto popt = cmd->add_option("-a,--proposal-name", propname, localized("Push a suspend transaction instead of normal transaction, specify its proposal name"));
    cmd->add_option("-b,--proposer", proposer, localized("Proposer public key"))->needs(popt);
}

template <typename T>
fc::variant
call(const std::string& url,
     const std::string& path,
     const T&           v,
     bool               raw_response = false) {
    try {
        evt::client::http::connection_param *cp = new evt::client::http::connection_param(context, parse_url(url) + path,
            no_verify ? false : true, headers, raw_response);

        return evt::client::http::do_http_call(*cp, fc::variant(v), print_request, print_response);
    }
    catch(boost::system::system_error& e) {
        if(url == ::url)
            std::cerr << localized("Failed to connect to evtd at ${u}; is evtd running?", ("u", url)) << std::endl;
        else if(url == ::wallet_url)
            std::cerr << localized("Failed to connect to evtwd at ${u}; is evtwd running?", ("u", url)) << std::endl;
        throw connection_exception(fc::log_messages{FC_LOG_MESSAGE(error, e.what())});
    }
}

template <typename T>
fc::variant
call(const std::string& path,
     const T&           v,
     bool               raw_response = false) {
    return call(url, path, fc::variant(v), raw_response);
}

template<>
fc::variant
call(const std::string& url,
     const std::string& path,
     bool               raw_response) {
    return call(url, path, fc::variant(), raw_response); 
}

void
set_execution_context(execution_context& exec_ctx) {
    auto acts = call(get_evt_actions, fc::variant()).as<std::vector<action_ver_type>>();
    for(auto& av : acts) {
        exec_ctx.set_version_unsafe(av.act, av.ver);
    }
}

template <typename T>
chain::action
create_action(const domain_name& domain, const domain_key& key, const T& value) {
    return action(domain, key, value);
}

evt::chain_apis::read_only::get_info_results
get_info() {
    return ::call(url, get_info_func, fc::variant()).as<evt::chain_apis::read_only::get_info_results>();
}

public_key_type
get_public_key(const std::string& key_or_ref) {
    static std::optional<fc::variant> pkeys;

    try {
        auto pkey = (public_key_type)key_or_ref;
        return pkey;
    }
    catch(...) {}

    if(!pkeys.has_value()) {
        pkeys = call(wallet_url, wallet_public_keys);
    }

    FC_ASSERT(key_or_ref.size() >= 2, "Not valid key reference");
    FC_ASSERT(key_or_ref[0] == '@', "Not valid key reference");

    try {
        int i = std::stoi(key_or_ref.substr(1));
        FC_ASSERT(i < (int)pkeys->size(), "Not valid key reference");
        return (*pkeys)[i].as<public_key_type>();
    }
    catch(...) {
        FC_ASSERT(false, "Not valid key reference");
    }
}

address
get_address(const std::string& addr_or_ref) {
    static std::optional<fc::variant> pkeys;

    try {
        auto addr = (address)addr_or_ref;
        return addr;
    }
    catch(...) {}

    if(!pkeys.has_value()) {
        pkeys = call(wallet_url, wallet_public_keys);
    }

    FC_ASSERT(addr_or_ref.size() >= 2, "Not valid key reference");
    FC_ASSERT(addr_or_ref[0] == '@', "Not valid key reference");

    try {
        int i = std::stoi(addr_or_ref.substr(1));
        FC_ASSERT(i < (int)pkeys->size(), "Not valid key reference");
        return address((*pkeys)[i].as<public_key_type>());
    }
    catch(...) {
        FC_ASSERT(false, "Not valid key reference");
    }
}

void
sign_transaction(signed_transaction& trx, const chain_id_type& chain_id) {
    // TODO better error checking
    const auto& public_keys   = call(wallet_url, wallet_public_keys);
    auto        get_arg       = fc::mutable_variant_object("transaction", (transaction)trx)("available_keys", public_keys);
    const auto& required_keys = call(url, get_required_keys, get_arg);
    // TODO determine chain id
    fc::variants sign_args  = {fc::variant(trx), required_keys["required_keys"], fc::variant(chain_id)};
    const auto&  signed_trx = call(wallet_url, wallet_sign_trx, sign_args);
    trx                     = signed_trx.as<signed_transaction>();
}

void
set_transaction_header(signed_transaction& trx, const evt::chain_apis::read_only::get_info_results& info) {
    trx.expiration = info.head_block_time + tx_expiration;

    // Set tapos, default to last irreversible block if it's not specified by the user
    block_id_type ref_block_id = info.last_irreversible_block_id;
    try {
        fc::variant ref_block;
        if(!tx_ref_block_num_or_id.empty()) {
            ref_block    = call(get_block_func, fc::mutable_variant_object("block_num_or_id", tx_ref_block_num_or_id));
            ref_block_id = ref_block["id"].as<block_id_type>();
        }
    }
    EVT_RETHROW_EXCEPTIONS(invalid_ref_block_exception, "Invalid reference block num or id: ${block_num_or_id}", ("block_num_or_id", tx_ref_block_num_or_id));
    trx.set_reference_block(ref_block_id);

    trx.max_charge = max_charge;
    trx.payer = get_address(payer);
}

signed_transaction
create_suspend_transaction(transaction& trx) {
    FC_ASSERT(!propname.empty());
    FC_ASSERT(!proposer.empty());

    auto ns = newsuspend();
    ns.name = (proposal_name)propname;
    ns.proposer = get_public_key(proposer);
    ns.trx = std::move(trx);
   
    auto signed_trx = signed_transaction();
    signed_trx.actions.emplace_back(create_action(N128(.suspend), (domain_key)propname, ns));
    return signed_trx;
}

fc::variant
push_transaction(signed_transaction& trx, packed_transaction::compression_type compression = packed_transaction::none) {
    auto info = get_info(); 
    set_transaction_header(trx, info);
    if(!propname.empty()) {
        // suspend transaction
        auto rtrx = (transaction)trx;
        trx = create_suspend_transaction(rtrx);
        // needs to set new transaction's header
        set_transaction_header(trx, info);
    }

    if(!tx_skip_sign) {
        sign_transaction(trx, info.chain_id);
    }

    if(get_charge_only) {
        auto c = call(get_charge, fc::mutable_variant_object("transaction",(transaction)trx)("sigs_num",trx.signatures.size()));
        return fc::variant(asset(c["charge"].as_int64(), evt_sym()));
    }

    if(!tx_dont_broadcast) {
        return call(push_txn_func, packed_transaction(trx, compression));
    }
    else {
        return fc::variant(trx);
    }
}

fc::variant
push_actions(fc::small_vector<chain::action, 4>&& actions, packed_transaction::compression_type compression = packed_transaction::none) {
    signed_transaction trx;
    trx.actions = std::forward<decltype(actions)>(actions);

    return push_transaction(trx, compression);
}

void
send_actions(fc::small_vector<chain::action, 4>&& actions, packed_transaction::compression_type compression = packed_transaction::none) {
    auto result = push_actions(std::forward<decltype(actions)>(actions), compression);
    print_result( result );
}

void
send_transaction(signed_transaction& trx, packed_transaction::compression_type compression = packed_transaction::none) {
    std::cout << fc::json::to_pretty_string(push_transaction(trx, compression)) << std::endl;
}

bool
local_port_used() {
    using namespace boost::asio;

    io_service ios;
    local::stream_protocol::endpoint endpoint(wallet_url.substr(strlen("unix://")));
    local::stream_protocol::socket socket(ios);
    boost::system::error_code ec;
    socket.connect(endpoint, ec);

    return !ec;
}

void
try_local_port(uint32_t duration) {
    using namespace std::chrono;
    auto start_time = duration_cast<std::chrono::milliseconds>(system_clock::now().time_since_epoch()).count();
    while(!local_port_used()) {
        if(duration_cast<std::chrono::milliseconds>(system_clock::now().time_since_epoch()).count() - start_time > duration) {
            std::cerr << "Unable to connect to evtwd, if evtwd is running please kill the process and try again.\n";
            throw connection_exception(fc::log_messages{FC_LOG_MESSAGE(error, "Unable to connect to evtwd")});
        }
    }
}

void
ensure_evtwd_running(CLI::App* app) {
    // version, net do not require evtwd
    if(tx_skip_sign || app->got_subcommand("version") || app->got_subcommand("net")) {
        return;
    }
    if(app->get_subcommand("create")->got_subcommand("key")) { // create key does not require wallet
        return;
    }
    if(app->get_subcommand("wallet")->got_subcommand("stop")) { // stop wallet not require wallet
        return;
    }
    if(app->got_subcommand("producer")) {
        auto prod = app->get_subcommand("producer");
        if(prod->got_subcommand("prodvote") || prod->got_subcommand("updsched")) {
            goto next;
        }
        return;
    }

next:
    if(wallet_url != default_wallet_url) {
        return;
    }

    if(local_port_used()) {
        return;
    }

    auto bin_path = boost::dll::program_location();
    bin_path.remove_filename();
    // This extra check is necessary when running evtc like this: ./evtc ...
    if(bin_path.filename_is_dot()) {
        bin_path.remove_filename();
    }
    bin_path.append("evtwd"); // if evtc and evtwd are in the same installation directory
    if(!boost::filesystem::exists(bin_path)) {
        bin_path.remove_filename().remove_filename().append("evtwd").append("evtwd");
    }

    if(boost::filesystem::exists(bin_path)) {
        bin_path = boost::filesystem::canonical(bin_path);

        auto pargs = vector<std::string>();
        pargs.push_back("--unix-socket-path");
        pargs.push_back(fc::path(determine_home_directory() / "evt-wallet/evtwd.sock").to_native_ansi_path());

        // namespace bp = boost::process;
        // ::boost::process::child evtwd(binPath, pargs,
        //                               bp::std_in.close(),
        //                               bp::std_out > bp::null,
        //                               bp::std_err > bp::null);
        // if(evtwd.running()) {
        //     std::cerr << binPath << " launched" << std::endl;
        //     evtwd.detach();
        //     try_local_port(2000);
        // }
        // else {
        //     std::cerr << "No wallet service listening on " << wallet_url << ". Failed to launch " << binPath << std::endl;
        // }

        auto argv = vector<char*>();
        argv.emplace_back((char*)bin_path.c_str());
        for(auto& parg : pargs) {
            argv.emplace_back((char*)parg.c_str());
        }
        argv.emplace_back(nullptr);

        auto pid = 0;
        if((pid = fork()) == 0) {
            // child
            if(setsid() < 0) {
                exit(-1);
            }

            close(STDIN_FILENO);
            close(STDOUT_FILENO);
            close(STDERR_FILENO);

            auto r = execv(bin_path.c_str(), argv.data());
            if(r == -1) {
                exit(-1);
            }
        }
        else if(pid < 0) {
            std::cerr << "Cannot fork to start evtwd" << std::endl;
        }
        else {
            std::cerr << bin_path << " launched" << std::endl;
            try_local_port(2000);
        }
    }
    else {
        std::cerr << "No wallet service listening on " << wallet_url
                  << ". Cannot automatically start evtwd because evtwd was not found." << std::endl;
    }
}

fc::variant
json_from_file_or_string(const string& file_or_str, fc::json::parse_type ptype = fc::json::legacy_parser) {
    regex r("^[ \t]*[\{\[]");
    if(!regex_search(file_or_str, r) && fc::is_regular_file(file_or_str)) {
        return fc::json::from_file(file_or_str, ptype);
    }
    else {
        return fc::json::from_string(file_or_str, ptype);
    }
}

auto parse_permission = [](auto& jsonOrFile) {
    try {
        auto           parsedPermission = json_from_file_or_string(jsonOrFile);
        permission_def permission;
        parsedPermission.as(permission);
        return permission;
    }
    EVT_RETHROW_EXCEPTIONS(permission_type_exception, "Fail to parse Permission JSON")
};

auto parse_group = [](auto& jsonOrFile) {
    try {
        auto      parsedGroup = json_from_file_or_string(jsonOrFile);
        group_def group;
        parsedGroup.as(group);
        return group;
    }
    EVT_RETHROW_EXCEPTIONS(group_type_exception, "Fail to parse Group JSON")
};

auto get_default_permission = [](const auto& pname, const auto& pkey) {
    auto p      = permission_def();
    auto a      = authorizer_weight();
    p.name      = pname;
    p.threshold = 1;
    if(pkey == public_key_type()) {
        // if no public key provided, assume it refer to owner group
        a.ref.set_owner();
        a.weight = 1;
    }
    else {
        a.ref.set_account(pkey);
        a.weight = 1;
    }
    p.authorizers.emplace_back(a);
    return p;
};

struct set_domain_subcommands {
    string name;
    string creator;
    string issue    = "default";
    string transfer = "default";
    string manage   = "default";

    set_domain_subcommands(CLI::App* actionRoot) {
        auto ndcmd = actionRoot->add_subcommand("create", localized("Create new domain"));
        ndcmd->add_option("name", name, localized("The name of new domain"))->required();
        ndcmd->add_option("creator", creator, localized("The public key of the creator"))->required();
        ndcmd->add_option("issue", issue, localized("JSON string or filename defining ISSUE permission"))->capture_default_str();
        ndcmd->add_option("transfer", transfer, localized("JSON string or filename defining TRANSFER permission"))->capture_default_str();
        ndcmd->add_option("manage", manage, localized("JSON string or filename defining MANAGE permission"))->capture_default_str();

        add_standard_transaction_options(ndcmd);

        ndcmd->callback([&] {
            newdomain nd;
            nd.name     = name128(name);
            nd.creator  = get_public_key(creator);
            nd.issue    = (issue == "default") ? get_default_permission("issue", nd.creator) : parse_permission(issue);
            nd.transfer = (transfer == "default") ? get_default_permission("transfer", public_key_type()) : parse_permission(transfer);
            nd.manage   = (manage == "default") ? get_default_permission("manage", nd.creator) : parse_permission(manage);

            auto act = create_action((domain_name)nd.name, N128(.create), nd);
            send_actions({act});
        });

        auto udcmd = actionRoot->add_subcommand("update", localized("Update existing domain"));
        udcmd->add_option("name", name, localized("The name of the updating domain"))->required();
        udcmd->add_option("-i,--issue", issue, localized("JSON string or filename defining ISSUE permission"))->capture_default_str();
        udcmd->add_option("-t,--transfer", transfer, localized("JSON string or filename defining TRANSFER permission"))->capture_default_str();
        udcmd->add_option("-m,--manage", manage, localized("JSON string or filename defining MANAGE permission"))->capture_default_str();

        add_standard_transaction_options(udcmd);

        udcmd->callback([&] {
            updatedomain ud;
            ud.name = name128(name);
            if(issue != "default") {
                ud.issue = parse_permission(issue);
            }
            if(transfer != "default") {
                ud.transfer = parse_permission(transfer);
            }
            if(manage != "default") {
                ud.manage = parse_permission(manage);
            }

            auto act = create_action((domain_name)ud.name, N128(.update), ud);
            send_actions({act});
        });
    }
};

struct set_issue_token_subcommand {
    string              domain;
    std::vector<string> names;
    std::vector<string> owner;

    set_issue_token_subcommand(CLI::App* actionRoot) {
        auto itcmd = actionRoot->add_subcommand("issue", localized("Issue new tokens in specific domain"));
        itcmd->add_option("domain", domain, localized("Name of the domain where token issued"))->required();
        itcmd->add_option("-n,--names", names, localized("Names of tokens will be issued"))->required();
        itcmd->add_option("owner", owner, localized("Owner that issued tokens belongs to"))->required();

        add_standard_transaction_options(itcmd);

        itcmd->callback([this] {
            issuetoken it;
            it.domain = name128(domain);
            std::transform(names.cbegin(), names.cend(), std::back_inserter(it.names), [](auto& str) { return name128(str); });
            std::transform(owner.cbegin(), owner.cend(), std::back_inserter(it.owner), [](auto& str) { return get_public_key(str); });

            auto act = create_action(it.domain, N128(.issue), it);
            send_actions({act});
        });
    }
};

struct set_token_subcommands {
    string              domain;
    string              name;
    std::vector<string> to;
    string              memo;

    set_token_subcommands(CLI::App* actionRoot) {
        auto ttcmd = actionRoot->add_subcommand("transfer", localized("Transfer token"));
        ttcmd->add_option("domain", domain, localized("Name of the domain where token existed"))->required();
        ttcmd->add_option("name", name, localized("Name of the token to be transfered"))->required();
        ttcmd->add_option("to", to, localized("User list receives this token"))->required();
        ttcmd->add_option("--memo,-m", memo, localized("Memo for this transfer"));

        add_standard_transaction_options(ttcmd);

        ttcmd->callback([this] {
            transfer tt;
            tt.domain = name128(domain);
            tt.name   = name128(name);
            tt.memo   = memo;
            std::transform(to.cbegin(), to.cend(), std::back_inserter(tt.to), [](auto& str) { return get_public_key(str); });

            auto act = create_action(tt.domain, (domain_key)tt.name, tt);
            send_actions({act});
        });

        auto dtcmd = actionRoot->add_subcommand("destroy", localized("Destroy one token"));
        dtcmd->add_option("domain", domain, localized("Name of the domain where token existed"))->required();
        dtcmd->add_option("name", name, localized("Name of the token to be destroyed"))->required();

        add_standard_transaction_options(dtcmd);

        dtcmd->callback([this] {
            destroytoken dt;
            dt.domain = name128(domain);
            dt.name   = name128(name);

            auto act = create_action(dt.domain, (domain_key)dt.name, dt);
            send_actions({act});
        });
    }
};

struct set_group_subcommands {
    string name;
    string key;
    string json;

    set_group_subcommands(CLI::App* actionRoot) {
        auto ngcmd = actionRoot->add_subcommand("create", localized("Create new group"));
        ngcmd->add_option("name", name, localized("Name of the group to be created"))->required();
        ngcmd->add_option("json", json, localized("JSON string or filename defining the group to be created"))->required();

        add_standard_transaction_options(ngcmd);

        ngcmd->callback([this] {
            newgroup ng;
            FC_ASSERT(!name.empty(), "Group name cannot be empty");
            ng.name = name;
            
            try {
                auto parsedGroup = json_from_file_or_string(json);
                parsedGroup.as(ng.group);
            }
            EVT_RETHROW_EXCEPTIONS(group_type_exception, "Fail to parse Group JSON")
            ng.group.name_ = name;

            auto act = create_action(N128(.group), (domain_key)ng.name, ng);
            send_actions({act});
        });

        auto ugcmd = actionRoot->add_subcommand("update", localized("Update specific permission group"));
        ugcmd->add_option("name", name, localized("Name of the group to be updated"))->required();
        ugcmd->add_option("json", json, localized("JSON string or filename defining the updated group"))->required();

        add_standard_transaction_options(ugcmd);

        ugcmd->callback([this] {
            updategroup ug;
            FC_ASSERT(!name.empty(), "Group name cannot be empty");
            ug.name = name;

            try {
                auto parsedGroup = json_from_file_or_string(json);
                parsedGroup.as(ug.group);
            }
            EVT_RETHROW_EXCEPTIONS(group_type_exception, "Fail to parse Group JSON")
            ug.group.name_ = name;

            auto act = create_action(N128(.group), (domain_key)ug.name, ug);
            send_actions({act});
        });
    }
};

struct set_fungible_subcommands {
    string fungible_name;
    string sym_name;
    string sym;
    string creator;
    string issue    = "default";
    string manage   = "default";
    string total_supply = "";
    string address;
    string number;
    string memo;

    symbol_id_type sym_id = 0;

    set_fungible_subcommands(CLI::App* actionRoot) {
        auto nfcmd = actionRoot->add_subcommand("create", localized("Create new fungible asset"));
        nfcmd->add_option("fungible-name", fungible_name, localized("The name of fungible asset"))->required();
        nfcmd->add_option("symbol-name", sym_name, localized("The name of symbol"))->required();
        nfcmd->add_option("symbol", sym, localized("The symbol of the new fungible asset"))->required();
        nfcmd->add_option("creator", creator, localized("The public key of the creator"))->required();
        nfcmd->add_option("total-supply", total_supply, localized("Total supply of this fungible asset"))->required();
        nfcmd->add_option("issue", issue, localized("JSON string or filename defining ISSUE permission"))->capture_default_str();
        nfcmd->add_option("manage", manage, localized("JSON string or filename defining MANAGE permission"))->capture_default_str();

        add_standard_transaction_options(nfcmd);

        nfcmd->callback([&] {
            newfungible nf;
            nf.name         = (name128)fungible_name;
            nf.sym_name     = (name128)sym_name;
            nf.sym          = symbol::from_string(sym);
            nf.creator      = get_public_key(creator);
            nf.issue        = (issue == "default") ? get_default_permission("issue", nf.creator) : parse_permission(issue);
            nf.manage       = (manage == "default") ? get_default_permission("manage", nf.creator) : parse_permission(manage);
            nf.total_supply = asset::from_string(total_supply);

            EVT_ASSERT(nf.total_supply.sym() == nf.sym, asset_type_exception, "Symbol and asset should be match");

            auto act = create_action(N128(.fungible), (domain_key)std::to_string(nf.sym.id()), nf);
            send_actions({act});
        });

        auto ufcmd = actionRoot->add_subcommand("update", localized("Update existing domain"));
        ufcmd->add_option("symbol-id", sym_id, localized("The symbol id of the updating fungible asset"))->required();
        ufcmd->add_option("-i,--issue", issue, localized("JSON string or filename defining ISSUE permission"))->capture_default_str();
        ufcmd->add_option("-m,--manage", manage, localized("JSON string or filename defining MANAGE permission"))->capture_default_str();

        add_standard_transaction_options(ufcmd);

        ufcmd->callback([&] {
            updfungible uf;
            uf.sym_id = sym_id;
            if(issue != "default") {
                uf.issue = parse_permission(issue);
            }
            if(manage != "default") {
                uf.manage = parse_permission(manage);
            }

            auto act = create_action(N128(.fungible), (domain_key)std::to_string(uf.sym_id), uf);
            send_actions({act});
        });

        auto ifcmd = actionRoot->add_subcommand("issue", localized("Issue fungible tokens to specific address"));
        ifcmd->add_option("address", address, localized("Address to receive issued asset"))->required();
        ifcmd->add_option("number", number, localized("Number of issue asset"))->required();
        ifcmd->add_option("--memo,-m", memo, localized("Memo for this transfer"));

        add_standard_transaction_options(ifcmd);

        ifcmd->callback([this] {
            issuefungible ifact;
            ifact.address = get_address(address);
            ifact.number  = asset::from_string(number);
            ifact.memo    = memo;

            auto act = create_action(N128(.fungible), (domain_key)std::to_string(ifact.number.sym().id()), ifact);
            send_actions({act});
        });

        auto rfcmd = actionRoot->add_subcommand("recycle", localized("Recycle fungible tokens back to issuance address"));
        rfcmd->add_option("number", number, localized("Number of recycle asset"))->required();
        rfcmd->add_option("--memo,-m", memo, localized("Memo for this action"));

        add_standard_transaction_options(rfcmd);

        rfcmd->callback([this] {
            recycleft rfact;
            rfact.address = get_address(address);
            rfact.number  = asset::from_string(number);
            rfact.memo    = memo;

            auto act = create_action(N128(.fungible), (domain_key)std::to_string(rfact.number.sym().id()), rfact);
            send_actions({act});
        });

        auto dfcmd = actionRoot->add_subcommand("destroy", localized("Destroy fungible tokens to reserved address"));
        dfcmd->add_option("number", number, localized("Number of destroy asset"))->required();
        dfcmd->add_option("--memo,-m", memo, localized("Memo for this action"));

        add_standard_transaction_options(dfcmd);

        dfcmd->callback([this] {
            destroyft dfact;
            dfact.address = get_address(address);
            dfact.number  = asset::from_string(number);
            dfact.memo    = memo;

            auto act = create_action(N128(.fungible), (domain_key)std::to_string(dfact.number.sym().id()), dfact);
            send_actions({act});
        });
    }
};

struct set_assets_subcommands {
    std::string from, to;
    std::string number;
    string      memo;

    set_assets_subcommands(CLI::App* actionRoot) {
        auto tfcmd = actionRoot->add_subcommand("transfer", localized("Transfer asset between addresses"));
        tfcmd->add_option("from", from, localized("Address where asset transfering from"))->required();
        tfcmd->add_option("to", to, localized("Address where asset transfering to"))->required();
        tfcmd->add_option("number", number, localized("Number of transfer asset"))->required();
        tfcmd->add_option("--memo,-m", memo, localized("Memo for this transfer"));

        add_standard_transaction_options(tfcmd);

        tfcmd->callback([this] {
            transferft tf;
            tf.from   = get_address(from);
            tf.to     = get_address(to);
            tf.number = asset::from_string(number);
            tf.memo   = memo;

            auto act = create_action(N128(.fungible), (domain_key)std::to_string(tf.number.sym().id()), tf);
            send_actions({act});
        });

        auto epcmd = actionRoot->add_subcommand("2pevt", localized("Convert EVT tokens to Pinned EVT tokens"));
        epcmd->add_option("from", from, localized("Address where asset transfering from"))->required();
        epcmd->add_option("to", to, localized("Address where asset transfering to"))->required();
        epcmd->add_option("number", number, localized("Number of transfer asset"))->required();
        epcmd->add_option("--memo,-m", memo, localized("Memo for this transfer"));

        add_standard_transaction_options(epcmd);

        epcmd->callback([this] {
            evt2pevt ep;
            ep.from   = get_address(from);
            ep.to     = get_address(to);
            ep.number = asset::from_string(number);
            ep.memo   = memo;

            FC_ASSERT(ep.number.sym() == evt_sym(), "Only EVT can be converted to Pinned EVT");

            auto act = create_action(N128(.fungible), (domain_key)std::to_string(ep.number.sym().id()), ep);
            send_actions({act});
        });

    }
};

std::string
try_get_meta_value_from_file(const std::string& file_or_str) {
    if(fc::is_regular_file(file_or_str)) {
        auto fs = std::ifstream(file_or_str);
        auto str = std::string((std::istreambuf_iterator<char>(fs)), std::istreambuf_iterator<char>());
        return str;
    }
    else {
        return file_or_str;
    }
}

struct set_meta_subcommands {
    string domain;
    string key;
    
    string metakey;
    string metavalue;
    string creator;

    set_meta_subcommands(CLI::App* actionRoot) {
        auto addcmds = [&](auto subcmd) {
            subcmd->add_option("meta-key", metakey, localized("Key of the metadata"))->required();
            subcmd->add_option("meta-value", metavalue, localized("File or text of the metadata"))->required();
            subcmd->add_option("creator", creator, localized("Public key of the metadata creator"))->required();
            add_standard_transaction_options(subcmd);
        };

        auto dmcmd = actionRoot->add_subcommand("domain", localized("Add metadata to one domain"));
        dmcmd->add_option("name", domain, localized("Name of domain adding to"))->required();
        addcmds(dmcmd);
        dmcmd->callback([this] {
            addmeta am;
            am.key = (meta_key)metakey;
            am.value = try_get_meta_value_from_file(metavalue);
            am.creator = get_public_key(creator);

            auto act = create_action((domain_name)domain, N128(.meta), am);
            send_actions({act});
        });

        auto gmcmd = actionRoot->add_subcommand("group", localized("Add metadata to one group"));
        gmcmd->add_option("name", key, localized("Name of group adding to"))->required();
        addcmds(gmcmd);
        gmcmd->callback([this] {
            addmeta am;
            am.key = (meta_key)metakey;
            am.value = try_get_meta_value_from_file(metavalue);
            am.creator = get_public_key(creator);

            auto act = create_action(N128(.group), (domain_key)key, am);
            send_actions({act});
        });

        auto tmcmd = actionRoot->add_subcommand("token", localized("Add metadata to one token"));
        tmcmd->add_option("domain", domain, localized("Domain name of token adding to"))->required();
        tmcmd->add_option("name", key, localized("Name of token adding to"))->required();
        addcmds(tmcmd);
        tmcmd->callback([this] {
            addmeta am;
            am.key = (meta_key)metakey;
            am.value = try_get_meta_value_from_file(metavalue);
            am.creator = get_public_key(creator);

            auto act = create_action((domain_name)domain, (domain_key)key, am);
            send_actions({act});
        });

        auto fmcmd = actionRoot->add_subcommand("fungible", localized("Add metadata to one fungible asset"));
        fmcmd->add_option("id", key, localized("Symbol id of fungible asset adding to"))->required();
        addcmds(fmcmd);
        fmcmd->callback([this] {
            addmeta am;
            am.key = (meta_key)metakey;
            am.value = try_get_meta_value_from_file(metavalue);
            am.creator = get_public_key(creator);

            auto act = create_action(N128(.fungible), (domain_key)key, am);
            send_actions({act});
        });
    }
};

struct set_suspend_subcommands {
    string name;
    string executor;

    set_suspend_subcommands(CLI::App* actionRoot) {
        auto adcmd = actionRoot->add_subcommand("approve", localized("Approve specific suspend transaction"));
        add_standard_transaction_options(adcmd);

        adcmd->add_option("name", name, localized("Proposal name of specific suspend transaction"))->required();
        adcmd->callback([this] {
            auto varsuspend = call(get_suspend_func, fc::mutable_variant_object("name", (proposal_name)name));
            auto suspend = suspend_def();

            auto exec_ctx = evt_execution_context_mock();
            set_execution_context(exec_ctx);

            auto abi = abi_serializer(evt_contract_abi(), std::chrono::hours(1));
            abi.from_variant(varsuspend, suspend, exec_ctx);

            auto public_keys = call(wallet_url, wallet_public_keys);
            auto get_arg     = fc::mutable_variant_object("name", (proposal_name)name)("available_keys", public_keys);
            
            auto required_keys = call(url, get_suspend_required_keys, get_arg);

            auto info = get_info();
            fc::variants sign_args  = {fc::variant(suspend.trx), required_keys["required_keys"], fc::variant(info.chain_id)};
            auto signed_trx = call(wallet_url, wallet_sign_trx, sign_args);
            
            auto trx = signed_trx.as<signed_transaction>();

            auto asact = aprvsuspend();
            asact.name = (proposal_name)name;
            asact.signatures = std::move(trx.signatures);

            auto act = create_action(N128(.suspend), (domain_key)asact.name, asact);
            send_actions({act});
        });

        auto cdcmd = actionRoot->add_subcommand("cancel", localized("Cancel specific suspend transaction"));
        add_standard_transaction_options(cdcmd);

        cdcmd->add_option("name", name, localized("Proposal name of specific suspend transaction"))->required();
        cdcmd->callback([this] {
            auto cdact = cancelsuspend();
            cdact.name = (proposal_name)name;

            auto act = create_action(N128(.suspend), (domain_key)cdact.name, cdact);
            send_actions({act});
        });

        auto edcmd = actionRoot->add_subcommand("execute", localized("Execute specific suspend transaction"));
        add_standard_transaction_options(edcmd);
        
        edcmd->add_option("name", name, localized("Proposal name of specific suspend transaction"))->required();
        edcmd->add_option("executor", executor, localized("Public key of executor for this suspend transaction"))->required();
        edcmd->callback([this] {
            auto esact = execsuspend(); 
            esact.name = (proposal_name)name;
            esact.executor = get_public_key(executor);

            auto act = create_action(N128(.suspend), (domain_key)esact.name, esact);
            send_actions({act});
        });
    }
};

lock_asset
parse_lockasset(const string& str) {
    vector<string> strs;
    boost::split(strs, str, boost::is_any_of(":"));
    FC_ASSERT(strs.size() >= 2);

    auto la = lock_asset();
    if(strs[0].substr(0, 1) == "@") {
        // FT Tokens
        auto fungible   = lockft_def();
        fungible.from   = get_address(strs[0]);
        fungible.amount = asset::from_string(strs[1]);

        la = fungible;
    }
    else {
        auto tokens   = locknft_def();
        tokens.domain = (name128)strs[0];
        for(auto i = 1u; i < strs.size(); i++) {
            tokens.names.emplace_back(name128(strs[i]));
        }

        la = tokens;
    }
    return la;
}

fc::time_point
parse_time_point_str(const std::string& str) {
    auto now = fc::time_point::now();
    return now + parse_time_span_str(str);
}

struct set_lock_subcommands {
    string         name;
    string         time;
    string         deadline;
    string         proposer;
    vector<string> assets;

    vector<string> conds;
    int            cond_threshold = 0;
    vector<string> succeed;
    vector<string> failed;

    string approver;
    string executor;

    set_lock_subcommands(CLI::App* actionRoot) {
        auto lacmd = actionRoot->add_subcommand("assets", localized("Lock assets for further operations"));
        lacmd->add_option("name", name, localized("Name of lock proposal"))->required();
        lacmd->add_option("time", time, localized("Unlock time since from now"))->required();
        lacmd->add_option("deadline", deadline, localized("Deadline time since from now"))->required();
        lacmd->add_option("proposer", proposer, localized("Proposer of lock proposal"))->required();
        lacmd->add_option("assets", assets, localized("Assets to be locked"))->required();

        lacmd->add_option("--cond", conds, localized("Condtional keys"))->required();
        lacmd->add_option("--cond-threshold", cond_threshold, localized("Condtional threshold"));
        lacmd->add_option("--succeed", succeed, localized("Keys to receive the assets when succeed"))->required();
        lacmd->add_option("--failed", failed, localized("Keys to receive the assets when timeout"))->required();

        add_standard_transaction_options(lacmd);

        lacmd->callback([this] {
            auto nl = newlock();

            nl.name        = (name128)name;
            nl.proposer    = get_public_key(proposer);
            nl.unlock_time = parse_time_point_str(time);
            nl.deadline    = parse_time_point_str(deadline);

            for(auto& ass : assets) {
                nl.assets.emplace_back(parse_lockasset(ass));
            }

            auto condkeys = lock_condkeys();
            for(auto& pkey : conds) {
                condkeys.cond_keys.emplace_back(get_public_key(pkey));
            }
            condkeys.threshold = cond_threshold;

            nl.condition = condkeys;

            for(auto& addr : succeed) {
                nl.succeed.emplace_back(get_address(addr));
            }
            for(auto& addr : failed) {
                nl.failed.emplace_back(get_address(addr));
            }

            auto act = create_action(N128(.lock), (domain_key)nl.name, nl);
            send_actions({act});
        });

        auto alcmd = actionRoot->add_subcommand("approve", localized("Approve one lock assets proposal"));
        alcmd->add_option("name", name, localized("Name of lock proposal"))->required();
        alcmd->add_option("approver", approver, localized("Public key of approver"))->required();

        add_standard_transaction_options(alcmd);

        alcmd->callback([this] {
            auto al = aprvlock();

            al.name     = (name128)name;
            al.approver = get_public_key(approver);
            al.data     = evt::chain::void_t();

            auto act = create_action(N128(.lock), (domain_key)al.name, al);
            send_actions({act});
        });
    }
};

producer_key
parse_prodkey(const string& str) {
    vector<string> strs;
    boost::split(strs, str, boost::is_any_of(":"));
    FC_ASSERT(strs.size() == 2);

    auto prodkey = producer_key();
    prodkey.producer_name = name128(strs[0]);
    prodkey.block_signing_key = get_public_key(strs[1]);

    return prodkey;
}

struct set_producer_subcommands {
    string  producer;
    string  confkey;
    int64_t confvalue;
    bool    postgres;
    string  prodsjson;

    vector<string> prodkeys;

    set_producer_subcommands(CLI::App* actionRoot) {
        auto pvcmd = actionRoot->add_subcommand("prodvote", localized("Producer votes for chain configuration"));
        pvcmd->add_option("name", producer, localized("Name of producer"))->required();
        pvcmd->add_option("key", confkey, localized("Key of config value to vote"))->required();
        pvcmd->add_option("value", confvalue, localized("Config value"))->required();

        add_standard_transaction_options(pvcmd);

        pvcmd->callback([this] {
            auto pvact = prodvote();
            pvact.producer = (account_name)producer;
            pvact.key      = (conf_key)confkey;
            pvact.value    = confvalue;

            auto act = create_action(N128(.prodvote), (domain_key)pvact.key, pvact);
            send_actions({act});
        });

        auto uscmd = actionRoot->add_subcommand("updsched", localized("Update producer scheduler"));
        uscmd->add_option("--json,-j", prodsjson, localized("Json file of producers"));
        uscmd->add_option("prodkeys", prodkeys, localized("Producer name and keys: ${name}:${key}"));

        add_standard_transaction_options(uscmd);

        uscmd->callback([this] {
            auto usact = updsched();
            if(!prodsjson.empty()) {
                auto var = json_from_file_or_string(prodsjson);
                from_variant(var, usact.producers);
            }
            else {
                FC_ASSERT(prodkeys.size() > 0);
                for(auto& prodkey : prodkeys) {
                    usact.producers.emplace_back(parse_prodkey(prodkey));
                }
            }
            
            auto act = create_action(N128(.prodsched), N128(.update), usact);
            send_actions({act});
        });

        auto ppcmd = actionRoot->add_subcommand("pause", localized("Pause current producing state"));
        ppcmd->callback([] {
            const auto& v = call(url, producer_pause);
            print_info(v);
        });

        auto rpcmd = actionRoot->add_subcommand("resume", localized("Resume producing"));
        rpcmd->callback([] {
            const auto& v = call(url, producer_resume);
            print_info(v);
        });

        auto isppcmd = actionRoot->add_subcommand("paused", localized("Get current producing state"));
        isppcmd->callback([] {
            const auto& v = call(url, producer_paused);
            print_info(v);
        });

        auto rocmd = actionRoot->add_subcommand("runtime", localized("Get current runtime options"));
        rocmd->callback([] {
            const auto& v = call(url, producer_runtime_opts);
            print_info(v);
        });

        auto cscmd = actionRoot->add_subcommand("snapshot", localized("Create a snapshot till current head block"));
        cscmd->add_flag("-p,--postgres", postgres, localized("Add postgres to snapshot"));
        cscmd->callback([this] {
            auto arg = fc::mutable_variant_object();
            arg["postgres"] = postgres;

            const auto& v = call(url, create_snapshot, arg);
            print_info(v);
        });

        auto ihcmd = actionRoot->add_subcommand("integrity_hash", localized("Get integrity hash till current head block"));
        ihcmd->callback([] {
            const auto& v = call(url, get_integrity_hash);
            print_info(v);
        });
    }
};

struct set_action_subcommand {
    string name;
    string domain;
    string key;
    string data;

    set_action_subcommand(CLI::App* actionRoot) {
        auto pacmd = actionRoot->add_subcommand("push", localized("Push a raw action to the chain"));
        pacmd->add_option("name", name, localized("Name of action to push"))->required();
        pacmd->add_option("domain", domain, localized("Domain of action to push"))->required();
        pacmd->add_option("key", key, localized("Key of action to push"))->required();
        pacmd->add_option("data", data, localized("Data of action to push, can be either json file or string"))->required();

        add_standard_transaction_options(pacmd);

        pacmd->callback([this] {
            auto vardata = fc::variant();
            if(fc::is_regular_file(data)) {
                vardata = fc::json::from_file(data);
            }
            else {
                vardata = fc::json::from_string(data);
            }

            auto exec_ctx = evt_execution_context_mock();
            set_execution_context(exec_ctx);

            auto type = exec_ctx.get_acttype_name((action_name)name);

            auto abi = abi_serializer(evt_contract_abi(), std::chrono::hours(1));
            auto rawdata = abi.variant_to_binary(type, vardata, exec_ctx);

            auto act = action((action_name)name, (domain_name)domain, (domain_key)key, rawdata);
            send_actions({act});
        });
    }
};

struct set_get_domain_subcommand {
    string name;

    set_get_domain_subcommand(CLI::App* actionRoot) {
        auto gdcmd = actionRoot->add_subcommand("domain", localized("Retrieve a domain information"));
        gdcmd->add_option("name", name, localized("Name of domain to be retrieved"))->required();

        gdcmd->callback([this] {
            auto arg = fc::mutable_variant_object("name", name);
            print_info(call(get_domain_func, arg));
        });
    }
};

struct set_get_token_subcommand {
    string domain;
    string name;
    int    skip = 0;
    int    take = 20;

    set_get_token_subcommand(CLI::App* actionRoot) {
        auto gtcmd = actionRoot->add_subcommand("token", localized("Retrieve a token information"));
        gtcmd->add_option("domain", domain, localized("Domain name of token to be retrieved"))->required();
        gtcmd->add_option("name", name, localized("Name of token to be retrieved"))->required();

        gtcmd->callback([this] {
            auto arg = fc::mutable_variant_object();
            arg.set("domain", domain);
            arg.set("name", name);
            print_info(call(get_token_func, arg));
        });

        auto gtscmd = actionRoot->add_subcommand("tokens", localized("Retrieve tokens in one domain"));
        gtscmd->add_option("domain", domain, localized("Domain name of token to be retrieved"))->required();
        gtscmd->add_option("--skip,-s", skip, localized("How many records should be skipped"));
        gtscmd->add_option("--take,-t", take, localized("How many records should be returned"));

        gtscmd->callback([this] {
            auto arg = fc::mutable_variant_object();
            arg.set("domain", domain);
            arg.set("skip", skip);
            arg.set("take", take);
            print_info(call(get_tokens_func, arg));
        });
    }
};

struct set_get_group_subcommand {
    string name;
    string key;

    set_get_group_subcommand(CLI::App* actionRoot) {
        auto ggcmd = actionRoot->add_subcommand("group", localized("Retrieve a permission group information"));
        ggcmd->add_option("name", name, localized("Name of group to be retrieved"))->required();

        ggcmd->callback([this] {
            FC_ASSERT(!name.empty(), "Group name cannot be empty");

            auto arg = fc::mutable_variant_object("name", name);
            print_info(call(get_group_func, arg));
        });
    }
};

struct set_get_fungible_subcommand {
    symbol_id_type id;
    string         address;

    set_get_fungible_subcommand(CLI::App* actionRoot) {
        auto gfcmd = actionRoot->add_subcommand("fungible", localized("Retrieve a fungible asset information"));
        gfcmd->add_option("id", id, localized("Symbol id of fungible asset to be retrieved"))->required();
        
        gfcmd->callback([this] {

            auto arg = fc::mutable_variant_object("id", id);
            print_info(call(get_fungible_func, arg));
        });

        auto gbcmd = actionRoot->add_subcommand("balance", localized("Retrieve fungible balance from an address"));
        gbcmd->add_option("address", address, localized("Address to query"))->required();
        gbcmd->add_option("symbol_id", id, localized("Specific symbol id to retrieve"))->required();

        gbcmd->callback([this] {
            FC_ASSERT(!address.empty(), "Address cannot be empty");

            auto arg = fc::mutable_variant_object("address", get_address(address))("sym_id",id);
            print_info(call(get_fungible_balance_func, arg));
        });

        auto gfpsb = actionRoot->add_subcommand("psvbonus", localized("Retrieve passive bonus registered to one fungible"));
        gfpsb->add_option("id", id, localized("Specific symbol id to retrieve"))->required();

        gfpsb->callback([this] {
            auto arg = fc::mutable_variant_object("id", id);
            print_info(call(get_fungible_psvbonus_func, arg));
        });
    }
};

struct set_get_suspend_subcommand {
    string name;

    set_get_suspend_subcommand(CLI::App* actionRoot) {
        auto gdcmd = actionRoot->add_subcommand("suspend", localized("Retrieve a suspend transaction information"));
        gdcmd->add_option("name", name, localized("Name of suspend transaction to be retrieved"))->required();

        gdcmd->callback([this] {
            auto arg = fc::mutable_variant_object("name", name);
            print_info(call(get_suspend_func, arg));
        });
    }
};

struct set_get_lock_subcommand {
    string name;

    set_get_lock_subcommand(CLI::App* actionRoot) {
        auto gdcmd = actionRoot->add_subcommand("lock", localized("Retrieve a lock assets proposal"));
        gdcmd->add_option("name", name, localized("Name of lock assets proposal to be retrieved"))->required();

        gdcmd->callback([this] {
            auto arg = fc::mutable_variant_object("name", name);
            print_info(call(get_lock_func, arg));
        });
    }
};

void
get_my_resources(const std::string& url) {
    auto info = get_info();

    auto keys = call(wallet_url, wallet_public_keys);
    auto args = fc::mutable_variant_object("keys", keys);

    print_info(call(url, args));
}

struct set_get_my_subcommands {
    int skip = -1;
    int take = -1;

    set_get_my_subcommands(CLI::App* actionRoot) {
        auto mycmd = actionRoot->add_subcommand("my", localized("Retrieve domains, tokens and groups created by user"));
        mycmd->require_subcommand();

        auto mydomain = mycmd->add_subcommand("domains", localized("Retrieve my created domains"));
        mydomain->callback([] {
            get_my_resources(get_my_domains);
        });

        auto mytoken = mycmd->add_subcommand("tokens", localized("Retrieve my owned tokens"));
        mytoken->callback([] {
            get_my_resources(get_my_tokens);
        });

        auto mygroup = mycmd->add_subcommand("groups", localized("Retrieve my created groups"));
        mygroup->callback([] {
            get_my_resources(get_my_groups);
        });

        auto myfungible = mycmd->add_subcommand("fungibles", localized("Retrieve my created fungibles"));
        myfungible->callback([] {
            get_my_resources(get_my_fungibles);
        });

        auto trxscmd = mycmd->add_subcommand("transactions", localized("Retrieve my transactions"));
        trxscmd->add_option("--skip,-s", skip, localized("How many records should be skipped"));
        trxscmd->add_option("--take,-t", take, localized("How many records should be returned"));

        trxscmd->callback([this] {
            auto args = mutable_variant_object();
            args["keys"] = call(wallet_url, wallet_public_keys);
            
            if(skip > 0) {
                args["skip"] = skip;
            }
            if(take > 0) {
                args["take"] = take;
            }

            print_info(call(get_transactions, args));
        });
    }
};

struct set_get_history_subcommands {
    string domain;
    string key;
    string addr;
    int    sym_id;

    std::vector<std::string> names;

    string trx_id;
    
    int skip = -1;
    int take = -1;

    set_get_history_subcommands(CLI::App* actionRoot) {
        auto hiscmd = actionRoot->add_subcommand("history", localized("Retrieve actions, transactions history"));
        hiscmd->require_subcommand();

        auto actscmd = hiscmd->add_subcommand("actions", localized("Retrieve actions by domian and key"));
        actscmd->add_option("domain", domain, localized("Domain of acitons to be retrieved"))->required();
        actscmd->add_option("key", key, localized("Key of acitons to be retrieved, leave empty to retrieve all actions"));
        actscmd->add_option("names", names, localized("Names of actions to be retrieved, leave empty to retrieve all actions"));
        actscmd->add_option("--skip,-s", skip, localized("How many records should be skipped"));
        actscmd->add_option("--take,-t", take, localized("How many records should be returned"));

        actscmd->callback([this] {
            auto args = mutable_variant_object();
            args["domain"] = domain;
            if(!key.empty()) {
                args["key"] = key;
            }

            if(!names.empty()) {
                args["names"] = names;
            }

            if(skip > 0) {
                args["skip"] = skip;
            }
            if(take > 0) {
                args["take"] = take;
            }

            print_info(call(get_actions, args));
        });

        auto trxcmd = hiscmd->add_subcommand("transaction", localized("Retrieve a transaction by its id"));
        trxcmd->add_option("id", trx_id, localized("Id of transaction to be retrieved"))->required();

        trxcmd->callback([this] {
            auto args = mutable_variant_object("id", trx_id);
            print_info(call(get_transaction, args));
        });

        auto trxactscmd = hiscmd->add_subcommand("trxactions", localized("Retrieve actions by transaction id"));
        trxactscmd->add_option("id", trx_id, localized("Id of transaction to be retrieved"))->required();

        trxactscmd->callback([this] {
            auto args = mutable_variant_object("id", trx_id);
            print_info(call(get_transaction_actions, args));
        });

        auto funcmd = hiscmd->add_subcommand("fungible", localized("Retrieve fungible actions history"));
        funcmd->add_option("sym_id", sym_id, localized("Symbol Id to be retrieved"))->required();
        funcmd->add_option("address", addr, localized("Address involved in fungible actions"));
        funcmd->add_option("--skip,-s", skip, localized("How many records should be skipped"));
        funcmd->add_option("--take,-t", take, localized("How many records should be returned"));

        funcmd->callback([this] {
            auto args = mutable_variant_object();
            args["sym_id"] = sym_id;
            if(!addr.empty()) {
                args["addr"] = get_address(addr);
            }

            if(skip > 0) {
                args["skip"] = skip;
            }
            if(take > 0) {
                args["take"] = take;
            }

            print_info(call(get_fungible_actions, args));
        });

        auto syncmd = hiscmd->add_subcommand("symbols", localized("Retrieve fungible symbol ids"));
        syncmd->add_option("--skip,-s", skip, localized("How many records should be skipped"));
        syncmd->add_option("--take,-t", take, localized("How many records should be returned"));

        syncmd->callback([this] {
            auto args = mutable_variant_object();
            if(skip > 0) {
                args["skip"] = skip;
            }
            if(take > 0) {
                args["take"] = take;
            }

            print_info(call(get_fungible_ids, args));
        });

        auto fbcmd = hiscmd->add_subcommand("balance", localized("Retrieve all the fungibles' balance for one address"));
        fbcmd->add_option("address", addr, localized("Address for query"))->required();

        fbcmd->callback([this] {
            FC_ASSERT(!addr.empty(), "Address cannot be empty");

            auto arg = fc::mutable_variant_object("addr", get_address(addr));
            print_info(call(get_fungibles_balance, arg));
        });
    }
};

CLI::callback_t header_opt_callback = [](CLI::results_t res) {
    vector<string>::iterator itr;

    for (itr = res.begin(); itr != res.end(); itr++) {
        headers.push_back(*itr);
    }

    return true;
};

class EVTApp : public CLI::App {
public:
    EVTApp(std::string app_description = "", std::string app_name = "")
        : CLI::App(app_description, app_name) {}

public:
    void
    pre_callback() override {
        ensure_evtwd_running(this);
    }
};

int
main(int argc, char** argv) {
    fc::path binPath = argv[0];
    if(binPath.is_relative()) {
        binPath = relative(binPath, fc::current_path());
    }

    setlocale(LC_ALL, "");
    bindtextdomain(locale_domain, locale_path);
    textdomain(locale_domain);
    context = evt::client::http::create_http_context();
    wallet_url = default_wallet_url;

    EVTApp app{"Command Line Interface to everiToken Client"};
    app.require_subcommand();

    app.add_option("-u,--url", url, localized("the http/https/unix-socket URL where evtd is running"))->capture_default_str();
    app.add_option("--wallet-url", wallet_url, localized("the http/https/unix-socket URL where evtwd is running"))->capture_default_str();

    app.add_option( "-r,--header", header_opt_callback, localized("pass specific HTTP header; repeat this option to pass multiple headers"));
    app.add_flag( "-n,--no-verify", no_verify, localized("don't verify peer certificate when using HTTPS"));

    bool verbose_errors = false;
    app.add_flag("-v,--verbose", verbose_errors, localized("output verbose actions on error"));
    app.add_flag("--print-request", print_request, localized("print HTTP request to STDERR"));
    app.add_flag("--print-response", print_response, localized("print HTTP response to STDERR"));

    app.set_help_all_flag("--help-all");

    auto version = app.add_subcommand("version", localized("Retrieve version information"));
    version->require_subcommand();

    version->add_subcommand("client", localized("Retrieve version information of the client"))->callback([] {
        std::cout << localized("Build version: ${ver}", ("ver", evt::client::config::version_str)) << std::endl;
    });

    // Create subcommand
    auto create = app.add_subcommand("create", localized("Create various items, on and off the blockchain"));
    create->require_subcommand();

    // create key
    auto create_key = create->add_subcommand("key", localized("Create a new keypair and print the public and private keys"))->callback([](){
        auto pk    = private_key_type::generate();
        auto privs = string(pk);
        auto pubs  = string(pk.get_public_key());
        std::cout << localized("Private key: ${key}", ("key", privs)) << std::endl;
        std::cout << localized("Public key: ${key}",  ("key", pubs))  << std::endl;
    });

    // Get subcommand
    auto get = app.add_subcommand("get", localized("Retrieve various items and information from the blockchain"));
    get->require_subcommand();

    // get info
    get->add_subcommand("info", localized("Get current blockchain information"))->callback([] {
        std::cout << fc::json::to_pretty_string(get_info()) << std::endl;
    });

    // get db info
    get->add_subcommand("dbinfo", localized("Get current underlying token database statistics"))->callback([] {
        std::cout << call(get_db_info_func, fc::variant(), true).get_string() << std::endl;
    });

    // get actions
    get->add_subcommand("actions", localized("Get current actions"))->callback([] {
        std::cout << fc::json::to_pretty_string(call(get_evt_actions, fc::variant())) << std::endl;
    });

    // get abi
    get->add_subcommand("abi", localized("Get current ABI"))->callback([] {
        std::cout << fc::json::to_pretty_string(call(get_evt_abi, fc::variant())) << std::endl;
    });

    // get apis
    get->add_subcommand("apis", localized("Get all available APIs for current node"))->callback([] {
        std::cout << fc::json::to_pretty_string(call(get_node_apis, fc::variant())) << std::endl;
    });

    // get block
    string blockArg;
    auto   getBlock = get->add_subcommand("block", localized("Retrieve a full block from the blockchain"));
    getBlock->add_option("block", blockArg, localized("The number or ID of the block to retrieve"))->required();
    getBlock->callback([&blockArg] {
        auto arg = fc::mutable_variant_object("block_num_or_id", blockArg);
        std::cout << fc::json::to_pretty_string(call(get_block_func, arg)) << std::endl;
    });

    set_get_domain_subcommand   get_domain(get);
    set_get_token_subcommand    get_token(get);
    set_get_group_subcommand    get_group(get);
    set_get_fungible_subcommand get_fungible(get);
    set_get_my_subcommands      get_my(get);
    set_get_history_subcommands get_history(get); 
    set_get_suspend_subcommand  get_suspend(get);
    set_get_lock_subcommand     get_lock(get);

    // get transaction
    string   trx_id;
    uint32_t block_num;
    bool     raw = false;

    auto get_trx = get->add_subcommand("transaction", localized("Retrieve a transaction by its id and block num"));
    get_trx->add_option("id", trx_id, localized("Id of transaction to be retrieved"))->required();
    get_trx->add_option("block_num", block_num, localized("Block num of transaction to be retrieved"))->required();
    get_trx->add_option("raw", raw, localized("Return actions in raw format"));

    get_trx->callback([&] {
        auto args = mutable_variant_object("id", trx_id)("block_num", block_num)("raw", raw);
        print_info(call(get_transaction_func, args));
    });


    // Net subcommand
    string new_host;
    auto   net = app.add_subcommand("net", localized("Interact with local p2p network connections"));
    net->require_subcommand();
    auto connect = net->add_subcommand("connect", localized("start a new connection to a peer"));
    connect->add_option("host", new_host, localized("The hostname:port to connect to."))->required();
    connect->callback([&] {
        const auto& v = call(net_connect, new_host);
        std::cout << fc::json::to_pretty_string(v) << std::endl;
    });

    auto disconnect = net->add_subcommand("disconnect", localized("close an existing connection"));
    disconnect->add_option("host", new_host, localized("The hostname:port to disconnect from."))->required();
    disconnect->callback([&] {
        const auto& v = call(net_disconnect, new_host);
        std::cout << fc::json::to_pretty_string(v) << std::endl;
    });

    auto status = net->add_subcommand("status", localized("status of existing connection"));
    status->add_option("host", new_host, localized("The hostname:port to query status of connection"))->required();
    status->callback([&] {
        const auto& v = call(net_status, new_host);
        std::cout << fc::json::to_pretty_string(v) << std::endl;
    });

    auto connections = net->add_subcommand("peers", localized("status of all existing peers"));
    connections->callback([&] {
        const auto& v = call(net_connections, new_host);
        std::cout << fc::json::to_pretty_string(v) << std::endl;
    });

    // domain subcommand
    auto domain = app.add_subcommand("domain", localized("Create or update a domain"));
    domain->require_subcommand();

    auto set_domain = set_domain_subcommands(domain);

    // token subcommand
    auto token = app.add_subcommand("token", localized("Issue or transfer tokens"));
    token->require_subcommand();

    auto set_issue_token = set_issue_token_subcommand(token);
    auto set_token = set_token_subcommands(token);

    // group subcommand
    auto group = app.add_subcommand("group", localized("Update pemission group"));
    group->require_subcommand();

    auto set_group = set_group_subcommands(group);

    // fungible subcommand
    auto fungible = app.add_subcommand("fungible", localized("Create or update a fungible asset"));
    fungible->require_subcommand();

    auto set_fungible = set_fungible_subcommands(fungible);

    // asset subcommand
    auto assets = app.add_subcommand("assets", localized("Issue and transfer assets between addresses"));
    assets->require_subcommand();

    auto set_assets = set_assets_subcommands(assets);

    // metas
    auto meta = app.add_subcommand("meta", localized("Add metadata to domain, group ot token"));
    meta->require_subcommand();

    auto set_meta = set_meta_subcommands(meta);

    // suspend
    auto suspend = app.add_subcommand("suspend", localized("Approve or cancel suspend transactions"));
    suspend->require_subcommand();

    auto set_suspend = set_suspend_subcommands(suspend);

    // lock
    auto lock = app.add_subcommand("lock", localized("Lock assets to perform further operations"));
    lock->require_subcommand();

    auto set_lock = set_lock_subcommands(lock);

    // producer
    auto producer = app.add_subcommand("producer", localized("Votes for producers"));
    producer->require_subcommand();

    auto set_producer = set_producer_subcommands(producer);

    // action
    auto action = app.add_subcommand("action", localized("Raw operations for actions"));
    action->require_subcommand();

    auto set_action = set_action_subcommand(action);

    // Wallet subcommand
    auto wallet = app.add_subcommand("wallet", localized("Interact with local wallet"));
    wallet->require_subcommand();
    // create wallet
    string wallet_name  = "default";
    auto   createWallet = wallet->add_subcommand("create", localized("Create a new wallet locally"));
    createWallet->add_option("-n,--name", wallet_name, localized("The name of the new wallet"))->capture_default_str();
    createWallet->callback([&wallet_name] {
        const auto& v = call(wallet_url, wallet_create, wallet_name);
        std::cout << localized("Creating wallet: ${wallet_name}", ("wallet_name", wallet_name)) << std::endl;
        std::cout << localized("Save password to use in the future to unlock this wallet.") << std::endl;
        std::cout << localized("Without password imported keys will not be retrievable.") << std::endl;
        std::cout << fc::json::to_pretty_string(v) << std::endl;
    });

    // open wallet
    auto openWallet = wallet->add_subcommand("open", localized("Open an existing wallet"));
    openWallet->add_option("-n,--name", wallet_name, localized("The name of the wallet to open"));
    openWallet->callback([&wallet_name] {
        call(wallet_url, wallet_open, wallet_name);
        std::cout << localized("Opened: ${wallet_name}", ("wallet_name", wallet_name)) << std::endl;
    });

    // lock wallet
    auto lockWallet = wallet->add_subcommand("lock", localized("Lock wallet"));
    lockWallet->add_option("-n,--name", wallet_name, localized("The name of the wallet to lock"));
    lockWallet->callback([&wallet_name] {
        call(wallet_url, wallet_lock, wallet_name);
        std::cout << localized("Locked: ${wallet_name}", ("wallet_name", wallet_name)) << std::endl;
    });

    // lock all wallets
    auto locakAllWallets = wallet->add_subcommand("lock_all", localized("Lock all unlocked wallets"));
    locakAllWallets->callback([] {
        call(wallet_url, wallet_lock_all);
        std::cout << localized("Locked All Wallets") << std::endl;
    });

    // unlock wallet
    string wallet_pw;
    auto   unlockWallet = wallet->add_subcommand("unlock", localized("Unlock wallet"));
    unlockWallet->add_option("-n,--name", wallet_name, localized("The name of the wallet to unlock"));
    unlockWallet->add_option("--password", wallet_pw, localized("The password returned by wallet create"));
    unlockWallet->callback([&wallet_name, &wallet_pw] {
        if(wallet_pw.size() == 0) {
            std::cout << localized("password: ");
            fc::set_console_echo(false);
            std::getline(std::cin, wallet_pw, '\n');
            fc::set_console_echo(true);
        }

        fc::variants vs = {fc::variant(wallet_name), fc::variant(wallet_pw)};
        call(wallet_url, wallet_unlock, vs);
        std::cout << localized("Unlocked: ${wallet_name}", ("wallet_name", wallet_name)) << std::endl;
    });

    // import keys into wallet
    string wallet_key_str;
    auto   importWallet = wallet->add_subcommand("import", localized("Import private key into wallet"));
    importWallet->add_option("-n,--name", wallet_name, localized("The name of the wallet to import key into"));
    importWallet->add_option("key", wallet_key_str, localized("Private key in WIF format to import"))->required();
    importWallet->callback([&wallet_name, &wallet_key_str] {
        private_key_type wallet_key;
        try {
            wallet_key = private_key_type(wallet_key_str);
        }
        catch(...) {
            EVT_THROW(private_key_type_exception, "Invalid private key: ${private_key}", ("private_key", wallet_key_str))
        }
        public_key_type pubkey = wallet_key.get_public_key();

        fc::variants vs = {fc::variant(wallet_name), fc::variant(wallet_key)};
        const auto&  v  = call(wallet_url, wallet_import_key, vs);
        std::cout << localized("imported private key for: ${pubkey}", ("pubkey", std::string(pubkey))) << std::endl;
        //std::cout << fc::json::to_pretty_string(v) << std::endl;
    });

    // remove keys from wallet
    string wallet_rm_key_str;
    auto removeKeyWallet = wallet->add_subcommand("remove_key", localized("Remove key from wallet"));
    removeKeyWallet->add_option("-n,--name", wallet_name, localized("The name of the wallet to remove key from"));
    removeKeyWallet->add_option("key", wallet_rm_key_str, localized("Public key in WIF format to remove"))->required();
    removeKeyWallet->add_option("--password", wallet_pw, localized("The password returned by wallet create"));
    removeKeyWallet->callback([&wallet_name, &wallet_pw, &wallet_rm_key_str] {
        if(wallet_pw.size() == 0) {
            std::cout << localized("password: ");
            fc::set_console_echo(false);
            std::getline( std::cin, wallet_pw, '\n' );
            fc::set_console_echo(true);
        }
        public_key_type pubkey;
        try {
            pubkey = public_key_type( wallet_rm_key_str );
        }
        catch (...) {
            EVT_THROW(public_key_type_exception, "Invalid public key: ${public_key}", ("public_key", wallet_rm_key_str))
        }
        fc::variants vs = {fc::variant(wallet_name), fc::variant(wallet_pw), fc::variant(wallet_rm_key_str)};
        call(wallet_url, wallet_remove_key, vs);
        std::cout << localized("removed private key for: ${pubkey}", ("pubkey", wallet_rm_key_str)) << std::endl;
    });

    // create a key within wallet
    string wallet_create_key_type;
    auto createKeyInWallet = wallet->add_subcommand("create_key", localized("Create private key within wallet"));
    createKeyInWallet->add_option("-n,--name", wallet_name, localized("The name of the wallet to create key into"))->capture_default_str();
    createKeyInWallet->add_option("key_type", wallet_create_key_type, localized("Key type to create (K1)"), true)->type_name("K1");
    createKeyInWallet->callback([&wallet_name, &wallet_create_key_type] {
        //an empty key type is allowed -- it will let the underlying wallet pick which type it prefers
        fc::variants vs = {fc::variant(wallet_name), fc::variant(wallet_create_key_type)};
        const auto& v = call(wallet_url, wallet_create_key, vs);
        std::cout << localized("Created new private key with a public key of: ") << fc::json::to_pretty_string(v) << std::endl;
    });

    // list wallets
    auto listWallet = wallet->add_subcommand("list", localized("List opened wallets, * = unlocked"));
    listWallet->callback([] {
        std::cout << localized("Wallets:") << std::endl;
        const auto& v = call(wallet_url, wallet_list);
        std::cout << fc::json::to_pretty_string(v) << std::endl;
    });

    // list keys
    auto listKeys = wallet->add_subcommand("keys", localized("List of public keys from all unlocked wallets."));
    listKeys->callback([] {
        const auto& v = call(wallet_url, wallet_public_keys);
        std::cout << fc::json::to_pretty_string(v) << std::endl;
    });

    // list private keys
    auto listPrivKeys = wallet->add_subcommand("private_keys", localized("List of private keys from an unlocked wallet in wif or PVT_R1 format."));
    listPrivKeys->add_option("-n,--name", wallet_name, localized("The name of the wallet to list keys from"))->capture_default_str();
    listPrivKeys->add_option("--password", wallet_pw, localized("The password returned by wallet create"));
    listPrivKeys->callback([&wallet_name, &wallet_pw] {
        if(wallet_pw.size() == 0) {
            std::cout << localized("password: ");
            fc::set_console_echo(false);
            std::getline(std::cin, wallet_pw, '\n');
            fc::set_console_echo(true);
        }
        fc::variants vs = {fc::variant(wallet_name), fc::variant(wallet_pw)};
        const auto& v = call(wallet_url, wallet_list_keys, vs);
        std::cout << fc::json::to_pretty_string(v) << std::endl;
    });

    // stop evtwd
    auto stopEvtwd = wallet->add_subcommand("stop", localized("Stop evtwd (doesn't work with evtd)."));
    stopEvtwd->callback([] {
        const auto& v = call(wallet_url, evtwd_stop);
        if (!v.is_object() || v.get_object().size() != 0) { //on success evtwd responds with empty object
            std::cerr << fc::json::to_pretty_string(v) << std::endl;
        }
        else {
            std::cout << "OK" << std::endl;
        }
    });

    // sign subcommand
    string trx_json_to_sign;
    string str_private_key;
    string str_chain_id;
    bool   push_trx = false;

    auto sign = app.add_subcommand("sign", localized("Sign a transaction"));
    sign->add_option("transaction", trx_json_to_sign,
                     localized("The JSON of the transaction to sign, or the name of a JSON file containing the transaction"), true)
        ->required();
    sign->add_option("-k,--private-key", str_private_key, localized("The private key that will be used to sign the transaction"));
    sign->add_option("-c,--chain-id", str_chain_id, localized("The chain id that will be used to sign the transaction"));
    sign->add_flag("-p,--push-transaction", push_trx, localized("Push transaction after signing"));

    sign->callback([&] {
        signed_transaction trx;

        std::optional<chain_id_type> chain_id;

        if(str_chain_id.size() == 0) {
            ilog("grabbing chain_id from evtd");
            auto info = get_info();
            chain_id = info.chain_id;
        }
        else {
            chain_id = chain_id_type(str_chain_id);
        }

        if(fc::is_regular_file(trx_json_to_sign)) {
            trx = fc::json::from_file(trx_json_to_sign).as<signed_transaction>();
        }
        else {
            trx = fc::json::from_string(trx_json_to_sign).as<signed_transaction>();
        }

        if(str_private_key.size() == 0) {
            std::cerr << localized("private key: ");
            fc::set_console_echo(false);
            std::getline(std::cin, str_private_key, '\n');
            fc::set_console_echo(true);
        }

        auto priv_key = fc::crypto::private_key::regenerate(*utilities::wif_to_key(str_private_key));
        trx.sign(priv_key, *chain_id);

        if(push_trx) {
            auto trx_result = call(push_txn_func, packed_transaction(trx, packed_transaction::none));
            std::cout << fc::json::to_pretty_string(trx_result) << std::endl;
        }
        else {
            std::cout << fc::json::to_pretty_string(trx) << std::endl;
        }
    });

    // Push subcommand
    auto push = app.add_subcommand("push", localized("Push arbitrary transactions to the blockchain"));
    push->require_subcommand();

    // push transaction
    string trx_to_push;
    auto   trxSubcommand = push->add_subcommand("transaction", localized("Push an arbitrary JSON transaction"));
    trxSubcommand->add_option("transaction", trx_to_push, localized("The JSON of the transaction to push, or the name of a JSON file containing the transaction"))->required();

    trxSubcommand->callback([&] {
        fc::variant trx_var;
        try {
            if(fc::is_regular_file(trx_to_push)) {
                trx_var = fc::json::from_file(trx_to_push);
            }
            else {
                trx_var = fc::json::from_string(trx_to_push);
            }
        }
        EVT_RETHROW_EXCEPTIONS(transaction_type_exception, "Fail to parse transaction JSON")
        signed_transaction trx        = trx_var.as<signed_transaction>();
        auto               trx_result = call(push_txn_func, packed_transaction(trx, packed_transaction::none));
        std::cout << fc::json::to_pretty_string(trx_result) << std::endl;
    });

    string trxsJson;
    auto   trxsSubcommand = push->add_subcommand("transactions", localized("Push an array of arbitrary JSON transactions"));
    trxsSubcommand->add_option("transactions", trxsJson, localized("The JSON array of the transactions to push"))->required();
    trxsSubcommand->callback([&] {
        fc::variant trx_var;
        try {
            trx_var = fc::json::from_string(trxsJson);
        }
        EVT_RETHROW_EXCEPTIONS(transaction_type_exception, "Fail to parse transaction JSON")
        auto trxs_result = call(push_txns_func, trx_var);
        std::cout << fc::json::to_pretty_string(trxs_result) << std::endl;
    });

    try {
        app.parse(argc, argv);
    }
    catch(const CLI::ParseError& e) {
        return app.exit(e);
    }
    catch(const explained_exception& e) {
        return 1;
    }
    catch(connection_exception& e) {
        if(verbose_errors) {
            elog("connect error: ${e}", ("e", e.to_detail_string()));
        }
    }
    catch(const fc::exception& e) {
        // attempt to extract the error code if one is present
        if(!print_recognized_errors(e, verbose_errors)) {
            // Error is not recognized
            if(!print_help_text(e) || verbose_errors) {
                elog("Failed with error: ${e}", ("e", verbose_errors ? e.to_detail_string() : e.to_string()));
            }
        }
        return 1;
    }

    return 0;
}
