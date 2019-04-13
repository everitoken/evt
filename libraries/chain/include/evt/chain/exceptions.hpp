/**
 *  @file
 *  @copyright defined in evt/LICENSE.txt
 */
#pragma once
#include <boost/core/typeinfo.hpp>
#include <fc/exception/exception.hpp>

#define EVT_ASSERT(expr, exc_type, FORMAT, ...)            \
    FC_MULTILINE_MACRO_BEGIN                               \
    if(!(expr))                                            \
        FC_THROW_EXCEPTION(exc_type, FORMAT, __VA_ARGS__); \
    FC_MULTILINE_MACRO_END

#define EVT_ASSERT2(expr, exc_type, FORMAT, ...)              \
    FC_MULTILINE_MACRO_BEGIN                                  \
    if(!(expr))                                               \
        FC_THROW_EXCEPTION2(exc_type, FORMAT, ##__VA_ARGS__); \
    FC_MULTILINE_MACRO_END

#define EVT_THROW(exc_type, FORMAT, ...)  throw exc_type(FC_LOG_MESSAGE(error, FORMAT, __VA_ARGS__));
#define EVT_THROW2(exc_type, FORMAT, ...) throw exc_type(FC_LOG_MESSAGE2(error, FORMAT, ##__VA_ARGS__));

/**
 * Macro inspired from FC_RETHROW_EXCEPTIONS
 * The main difference here is that if the exception caught isn't of type "chain_exception"
 * This macro will rethrow the exception as the specified "exception_type"
 */
#define EVT_RETHROW_EXCEPTIONS(exception_type, FORMAT, ...)                                                 \
    catch(const boost::interprocess::bad_alloc&) {                                                          \
        throw;                                                                                              \
    }                                                                                                       \
    catch(const fc::unrecoverable_exception&) {                                                             \
        throw;                                                                                              \
    }                                                                                                       \
    catch(chain_exception& e) {                                                                             \
        FC_RETHROW_EXCEPTION(e, warn, FORMAT, __VA_ARGS__);                                                 \
    }                                                                                                       \
    catch(fc::exception& e) {                                                                               \
        exception_type new_exception(FC_LOG_MESSAGE(warn, FORMAT, __VA_ARGS__));                            \
        for(const auto& log : e.get_log()) {                                                                \
            new_exception.append_log(log);                                                                  \
        }                                                                                                   \
        throw new_exception;                                                                                \
    }                                                                                                       \
    catch(const std::exception& e) {                                                                        \
        exception_type fce(FC_LOG_MESSAGE(warn, FORMAT " (${what})", __VA_ARGS__("what", e.what())));       \
        throw fce;                                                                                          \
    }                                                                                                       \
    catch(...) {                                                                                            \
        throw fc::unhandled_exception(FC_LOG_MESSAGE(warn, FORMAT, __VA_ARGS__), std::current_exception()); \
    }

#define EVT_RETHROW_EXCEPTIONS2(exception_type, FORMAT, ...)                                                 \
    catch(const boost::interprocess::bad_alloc&) {                                                           \
        throw;                                                                                               \
    }                                                                                                        \
    catch(const fc::unrecoverable_exception&) {                                                              \
        throw;                                                                                               \
    }                                                                                                        \
    catch(chain_exception& e) {                                                                              \
        FC_RETHROW_EXCEPTION2(e, warn, FORMAT, __VA_ARGS__);                                                 \
    }                                                                                                        \
    catch(fc::exception& e) {                                                                                \
        exception_type new_exception(FC_LOG_MESSAGE2(warn, FORMAT, __VA_ARGS__));                            \
        for(const auto& log : e.get_log()) {                                                                 \
            new_exception.append_log(log);                                                                   \
        }                                                                                                    \
        throw new_exception;                                                                                 \
    }                                                                                                        \
    catch(const std::exception& e) {                                                                         \
        exception_type fce(FC_LOG_MESSAGE2(warn, FORMAT " ({})", ##__VA_ARGS__, e.what()));                  \
        throw fce;                                                                                           \
    }                                                                                                        \
    catch(...) {                                                                                             \
        throw fc::unhandled_exception(FC_LOG_MESSAGE2(warn, FORMAT, __VA_ARGS__), std::current_exception()); \
    }

/**
 * Macro inspired from FC_CAPTURE_AND_RETHROW
 * The main difference here is that if the exception caught isn't of type "chain_exception"
 * This macro will rethrow the exception as the specified "exception_type"
 */
#define EVT_CAPTURE_AND_RETHROW(exception_type, ...)                                                               \
    catch(const boost::interprocess::bad_alloc&) {                                                                 \
        throw;                                                                                                     \
    }                                                                                                              \
    catch(const fc::unrecoverable_exception&) {                                                                    \
        throw;                                                                                                     \
    }                                                                                                              \
    catch(chain_exception & e) {                                                                                   \
        FC_RETHROW_EXCEPTION(e, warn, "", FC_FORMAT_ARG_PARAMS(__VA_ARGS__));                                      \
    }                                                                                                              \
    catch(fc::exception & e) {                                                                                     \
        exception_type new_exception(e.get_log());                                                                 \
        throw new_exception;                                                                                       \
    }                                                                                                              \
    catch(const std::exception& e) {                                                                               \
        exception_type fce(FC_LOG_MESSAGE(warn, "${what}: ", FC_FORMAT_ARG_PARAMS(__VA_ARGS__)("what", e.what())), \
                           fc::std_exception_code, BOOST_CORE_TYPEID(decltype(e)).name(), e.what());               \
        throw fce;                                                                                                 \
    }                                                                                                              \
    catch(...) {                                                                                                   \
        throw fc::unhandled_exception(FC_LOG_MESSAGE(warn, "", FC_FORMAT_ARG_PARAMS(__VA_ARGS__)),                 \
                                      std::current_exception());                                                   \
    }

#define EVT_RECODE_EXC(cause_type, effect_type)    \
    catch(const cause_type& e) {                   \
        throw(effect_type(e.what(), e.get_log())); \
    }

namespace evt { namespace chain {

FC_DECLARE_EXCEPTION( chain_exception, 3000000, "blockchain exception" );

FC_DECLARE_DERIVED_EXCEPTION( database_exception, chain_exception, 3010000, "Database exception" );

FC_DECLARE_DERIVED_EXCEPTION( block_validate_exception,    chain_exception,          3020000, "block validation exception" );
FC_DECLARE_DERIVED_EXCEPTION( unlinkable_block_exception,  block_validate_exception, 3020001, "Unlinkable block" );
FC_DECLARE_DERIVED_EXCEPTION( block_tx_output_exception,   block_validate_exception, 3020002, "Transaction outputs in block do not match transaction outputs from applying block" );
FC_DECLARE_DERIVED_EXCEPTION( block_concurrency_exception, block_validate_exception, 3020003, "Block does not guarantee concurrent execution without conflicts" );
FC_DECLARE_DERIVED_EXCEPTION( block_lock_exception,        block_validate_exception, 3020004, "Shard locks in block are incorrect or mal-formed" );
FC_DECLARE_DERIVED_EXCEPTION( block_resource_exhausted,    block_validate_exception, 3020005, "Block exhausted allowed resources" );
FC_DECLARE_DERIVED_EXCEPTION( block_too_old_exception,     block_validate_exception, 3020006, "Block is too old to push" );
FC_DECLARE_DERIVED_EXCEPTION( block_from_the_future,       block_validate_exception, 3020007, "Block is from the future" );
FC_DECLARE_DERIVED_EXCEPTION( wrong_signing_key,           block_validate_exception, 3020008, "Block is not signed with expected key" );
FC_DECLARE_DERIVED_EXCEPTION( wrong_producer,              block_validate_exception, 3020009, "Block is not signed by expected producer" );

FC_DECLARE_DERIVED_EXCEPTION( transaction_exception,           chain_exception,       3030000, "transaction validation exception" );
FC_DECLARE_DERIVED_EXCEPTION( tx_duplicate,                    transaction_exception, 3030001, "duplicate transaction" );
FC_DECLARE_DERIVED_EXCEPTION( tx_decompression_error,          transaction_exception, 3030002, "Error decompressing transaction" );
FC_DECLARE_DERIVED_EXCEPTION( expired_tx_exception,            transaction_exception, 3030003, "Expired Transaction" );
FC_DECLARE_DERIVED_EXCEPTION( tx_exp_too_far_exception,        transaction_exception, 3030004, "Transaction Expiration Too Far" );
FC_DECLARE_DERIVED_EXCEPTION( invalid_ref_block_exception,     transaction_exception, 3030005, "Invalid Reference Block" );
FC_DECLARE_DERIVED_EXCEPTION( tx_apply_exception,              transaction_exception, 3030006, "Transaction Apply Exception" );
FC_DECLARE_DERIVED_EXCEPTION( tx_receipt_inconsistent_status,  transaction_exception, 3030007, "Transaction receipt applied status does not match received status." );
FC_DECLARE_DERIVED_EXCEPTION( tx_no_action,                    transaction_exception, 3030008, "transaction should have at least one normal action." );
FC_DECLARE_DERIVED_EXCEPTION( deadline_exception,              transaction_exception, 3030009, "transaction is timeout." );
FC_DECLARE_DERIVED_EXCEPTION( max_charge_exceeded_exception,   transaction_exception, 3030010, "exceeded max charge paid");
FC_DECLARE_DERIVED_EXCEPTION( charge_exceeded_exception,       transaction_exception, 3030011, "exceeded remaining EVT & Pinned EVT tokens" );
FC_DECLARE_DERIVED_EXCEPTION( payer_exception,                 transaction_exception, 3030012, "Invalid payer" );
FC_DECLARE_DERIVED_EXCEPTION( too_many_tx_at_once,             transaction_exception, 3030013, "Pushing too many transactions at once" );
FC_DECLARE_DERIVED_EXCEPTION( tx_too_big,                      transaction_exception, 3030014, "Transaction is too big" );
FC_DECLARE_DERIVED_EXCEPTION( unknown_transaction_compression, transaction_exception, 3030015, "Unknown transaction compression" );

FC_DECLARE_DERIVED_EXCEPTION( action_exception,           chain_exception,  3040000, "action exception" );
FC_DECLARE_DERIVED_EXCEPTION( action_authorize_exception, action_exception, 3040001, "invalid action authorization" );
FC_DECLARE_DERIVED_EXCEPTION( action_args_exception,      action_exception, 3040002, "Invalid arguments for action" );
FC_DECLARE_DERIVED_EXCEPTION( name_reserved_exception,    action_exception, 3040003, "Name is reserved." );
FC_DECLARE_DERIVED_EXCEPTION( address_reserved_exception, action_exception, 3040004, "Address is reserved." );
FC_DECLARE_DERIVED_EXCEPTION( asset_symbol_exception,     action_exception, 3040005, "Invalid symbol of asset" );

FC_DECLARE_DERIVED_EXCEPTION( domain_exception,               action_exception, 3040100, "Domain exception" );
FC_DECLARE_DERIVED_EXCEPTION( unknown_domain_exception,       domain_exception, 3040101, "Domain does not exist." );
FC_DECLARE_DERIVED_EXCEPTION( domain_duplicate_exception,     domain_exception, 3040102, "Domain already exists." );
FC_DECLARE_DERIVED_EXCEPTION( domain_name_exception,          domain_exception, 3040103, "Invalid domain name" );
FC_DECLARE_DERIVED_EXCEPTION( domain_cannot_update_exception, domain_exception, 3040104, "Some parts of this domain cannot be updated due to some limitations" );

FC_DECLARE_DERIVED_EXCEPTION( token_exception,                action_exception, 3040200, "Token exception" );
FC_DECLARE_DERIVED_EXCEPTION( unknown_token_exception,        token_exception,  3040201, "Token does not exist." );
FC_DECLARE_DERIVED_EXCEPTION( token_duplicate_exception,      token_exception,  3040202, "Token already exists." );
FC_DECLARE_DERIVED_EXCEPTION( token_name_exception,           token_exception,  3040203, "Invalid token name" );
FC_DECLARE_DERIVED_EXCEPTION( token_owner_exception,          token_exception,  3040204, "Token owner cannot be empty." );
FC_DECLARE_DERIVED_EXCEPTION( token_destroyed_exception,      token_exception,  3040205, "Token is destroyed." );
FC_DECLARE_DERIVED_EXCEPTION( token_locked_exception,         token_exception,  3040206, "Locked token cannot be transfered." );
FC_DECLARE_DERIVED_EXCEPTION( token_cannot_destroy_exception, token_exception,  3040207, "Token in this domain cannot be destroyed." );

FC_DECLARE_DERIVED_EXCEPTION( group_exception,           action_exception, 3040300, "Group exception" );
FC_DECLARE_DERIVED_EXCEPTION( unknown_group_exception,   group_exception,  3040301, "Group does not exist." );
FC_DECLARE_DERIVED_EXCEPTION( group_duplicate_exception, group_exception,  3040302, "Group already exists." );
FC_DECLARE_DERIVED_EXCEPTION( group_name_exception,      group_exception,  3040303, "Invalid group name" );
FC_DECLARE_DERIVED_EXCEPTION( group_key_exception,       group_exception,  3040304, "Group key is reserved to update this group." );

FC_DECLARE_DERIVED_EXCEPTION( fungible_exception,               action_exception,   3040400, "FT exception" );
FC_DECLARE_DERIVED_EXCEPTION( unknown_fungible_exception,       fungible_exception, 3040401, "FT does not exist." );
FC_DECLARE_DERIVED_EXCEPTION( fungible_duplicate_exception,     fungible_exception, 3040402, "FT already exists." );
FC_DECLARE_DERIVED_EXCEPTION( fungible_name_exception,          fungible_exception, 3040403, "Invalid FT asset name" );
FC_DECLARE_DERIVED_EXCEPTION( fungible_symbol_exception,        fungible_exception, 3040404, "Invalid FT asset symbol" );
FC_DECLARE_DERIVED_EXCEPTION( fungible_supply_exception,        fungible_exception, 3040405, "Invalid FT supply" );
FC_DECLARE_DERIVED_EXCEPTION( fungible_address_exception,       fungible_exception, 3040406, "Invalid address" );
FC_DECLARE_DERIVED_EXCEPTION( math_overflow_exception,          fungible_exception, 3040407, "Operations resulted in overflow." );
FC_DECLARE_DERIVED_EXCEPTION( balance_exception,                fungible_exception, 3040408, "Not enough balance left." );
FC_DECLARE_DERIVED_EXCEPTION( fungible_cannot_update_exception, fungible_exception, 3040409, "Some parts of this FT cannot be updated due to some limitations" );

FC_DECLARE_DERIVED_EXCEPTION( suspend_exception,                   action_exception,  3040500, "Suspend exception" );
FC_DECLARE_DERIVED_EXCEPTION( unknown_suspend_exception,           suspend_exception, 3040501, "Suspend transaction does not exist." );
FC_DECLARE_DERIVED_EXCEPTION( suspend_duplicate_exception,         suspend_exception, 3040502, "Suspend transaction already exists." );
FC_DECLARE_DERIVED_EXCEPTION( suspend_status_exception,            suspend_exception, 3040503, "Suspend transaction is not in proper status." );
FC_DECLARE_DERIVED_EXCEPTION( suspend_proposer_key_exception,      suspend_exception, 3040504, "Proposer needs to sign his key." );
FC_DECLARE_DERIVED_EXCEPTION( suspend_duplicate_key_exception,     suspend_exception, 3040505, "Same keys are already signed this suspend transaction." );
FC_DECLARE_DERIVED_EXCEPTION( suspend_expired_tx_exception,        suspend_exception, 3040506, "Suspend transaction is expired." );
FC_DECLARE_DERIVED_EXCEPTION( suspend_not_required_keys_exception, suspend_exception, 3040507, "Provided keys are not required." );
FC_DECLARE_DERIVED_EXCEPTION( suspend_executor_exception,          suspend_exception, 3040508, "Invalid executor." );
FC_DECLARE_DERIVED_EXCEPTION( suspend_invalid_action_exception,    suspend_exception, 3040509, "Action is not valid for suspend transaction." );
FC_DECLARE_DERIVED_EXCEPTION( proposal_name_exception,             suspend_exception, 3040510, "Invalid proposal name" );

FC_DECLARE_DERIVED_EXCEPTION( meta_exception,         action_exception, 3040600, "Meta exception" );
FC_DECLARE_DERIVED_EXCEPTION( meta_key_exception,     meta_exception,   3040601, "Invalid meta key" );
FC_DECLARE_DERIVED_EXCEPTION( meta_value_exception,   meta_exception,   3040602, "Invalid meta value" );
FC_DECLARE_DERIVED_EXCEPTION( meta_involve_exception, meta_exception,   3040603, "Creator is not involved." );

FC_DECLARE_DERIVED_EXCEPTION( evt_link_exception,            action_exception,   3040700, "EVT-Link exception" );
FC_DECLARE_DERIVED_EXCEPTION( evt_link_no_key_exception,     evt_link_exception, 3040701, "Specific segment key is not in this evt-link." );
FC_DECLARE_DERIVED_EXCEPTION( evt_link_version_exception,    evt_link_exception, 3040702, "EVT-Link version is not valid.");
FC_DECLARE_DERIVED_EXCEPTION( evt_link_id_exception,         evt_link_exception, 3040703, "EVT-Link id is not valid.");
FC_DECLARE_DERIVED_EXCEPTION( evt_link_dupe_exception,       evt_link_exception, 3040704, "Duplicate EVT-Link.");
FC_DECLARE_DERIVED_EXCEPTION( evt_link_type_exception,       evt_link_exception, 3040705, "Invalid EVT-Link type.");
FC_DECLARE_DERIVED_EXCEPTION( evt_link_expiration_exception, evt_link_exception, 3040706, "EVT-Link is expired.");
FC_DECLARE_DERIVED_EXCEPTION( evt_link_existed_exception,    evt_link_exception, 3040707, "EVT-Link is not existed.");
FC_DECLARE_DERIVED_EXCEPTION( everipass_exception,           evt_link_exception, 3040708, "everiPass failed.");
FC_DECLARE_DERIVED_EXCEPTION( everipay_exception,            evt_link_exception, 3040709, "everiPay failed.");

FC_DECLARE_DERIVED_EXCEPTION( prodvote_exception,          action_exception,   3040800, "Producer vote exception" );
FC_DECLARE_DERIVED_EXCEPTION( prodvote_key_exception,      prodvote_exception, 3040801, "Unknown prodvote conf key.");
FC_DECLARE_DERIVED_EXCEPTION( prodvote_value_exception,    prodvote_exception, 3040802, "Invalid prodvote conf value.");
FC_DECLARE_DERIVED_EXCEPTION( prodvote_producer_exception, prodvote_exception, 3040803, "Invalid producer.");

FC_DECLARE_DERIVED_EXCEPTION( lock_exception,               action_exception, 3040900, "Lock assets exception" );
FC_DECLARE_DERIVED_EXCEPTION( unknown_lock_exception,       lock_exception,   3040901, "Unknown lock assets proposal" );
FC_DECLARE_DERIVED_EXCEPTION( lock_duplicate_exception,     lock_exception,   3040902, "Lock assets proposal already exists." );
FC_DECLARE_DERIVED_EXCEPTION( lock_unlock_time_exception,   lock_exception,   3040903, "Invalid unlock time." );
FC_DECLARE_DERIVED_EXCEPTION( lock_deadline_exception,      lock_exception,   3040904, "Invalid deadline." );
FC_DECLARE_DERIVED_EXCEPTION( lock_assets_exception,        lock_exception,   3040905, "Invalid lock assets." );
FC_DECLARE_DERIVED_EXCEPTION( lock_address_exception,       lock_exception,   3040906, "Invalid lock address." );
FC_DECLARE_DERIVED_EXCEPTION( lock_condition_exception,     lock_exception,   3040907, "Invalid lock condition." );
FC_DECLARE_DERIVED_EXCEPTION( lock_expired_exception,       lock_exception,   3040908, "Lock assets proposal is expired." );
FC_DECLARE_DERIVED_EXCEPTION( lock_aprv_data_exception,     lock_exception,   3040909, "Approve data is not valid." );
FC_DECLARE_DERIVED_EXCEPTION( lock_duplicate_key_exception, lock_exception,   3040910, "Some keys are already signed this lock assets proposal." );
FC_DECLARE_DERIVED_EXCEPTION( lock_not_reach_unlock_time,   lock_exception,   3040911, "Unlock time is not reach." );
FC_DECLARE_DERIVED_EXCEPTION( lock_not_reach_deadline,      lock_exception,   3040912, "Deadline is not reach." );

FC_DECLARE_DERIVED_EXCEPTION( bonus_exception,                action_exception, 3041000, "Bonus exception" );
FC_DECLARE_DERIVED_EXCEPTION( unknown_bonus_exception,        bonus_exception,  3041001, "Unknown bonus exception" );
FC_DECLARE_DERIVED_EXCEPTION( bonus_dupe_exception,           bonus_exception,  3041002, "Duplicate bonus exception" );
FC_DECLARE_DERIVED_EXCEPTION( bonus_asset_exception,          bonus_exception,  3041003, "Duplicate bonus exception" );
FC_DECLARE_DERIVED_EXCEPTION( bonus_rules_exception,          bonus_exception,  3041004, "Invalid rules for bonus" );
FC_DECLARE_DERIVED_EXCEPTION( bonus_rules_order_exception,    bonus_exception,  3041005, "Invalid order of rules for bonus" );
FC_DECLARE_DERIVED_EXCEPTION( bonus_percent_value_exception,  bonus_exception,  3041006, "Invalid percent value" );
FC_DECLARE_DERIVED_EXCEPTION( bonus_percent_result_exception, bonus_exception,  3041007, "Invalid result after calculating the percent" );
FC_DECLARE_DERIVED_EXCEPTION( bonus_rules_not_fullfill,       bonus_exception,  3041008, "Rules are not fullfile the provided amount" );
FC_DECLARE_DERIVED_EXCEPTION( bonus_receiver_exception,       bonus_exception,  3041009, "Invalid receiver for bonus" );
FC_DECLARE_DERIVED_EXCEPTION( bonus_latest_not_expired,       bonus_exception,  3041010, "Latest bonus distribution is not expired" );
FC_DECLARE_DERIVED_EXCEPTION( bonus_unreached_dist_threshold, bonus_exception,  3041011, "Distribution threshold is unreached" );
FC_DECLARE_DERIVED_EXCEPTION( bonus_method_exeption,          bonus_exception,  3041012, "Invalid method for passive bonus" );

FC_DECLARE_DERIVED_EXCEPTION( producer_exception,                      chain_exception,    3050000, "Producer exception" );
FC_DECLARE_DERIVED_EXCEPTION( producer_priv_key_not_found,             producer_exception, 3050001, "Producer private key is not available" );
FC_DECLARE_DERIVED_EXCEPTION( missing_pending_block_state,             producer_exception, 3050002, "Pending block state is missing" );
FC_DECLARE_DERIVED_EXCEPTION( producer_double_confirm,                 producer_exception, 3050003, "Producer is double confirming known range" );
FC_DECLARE_DERIVED_EXCEPTION( producer_schedule_exception,             producer_exception, 3050004, "Producer schedule exception" );
FC_DECLARE_DERIVED_EXCEPTION( producer_not_in_schedule,                producer_exception, 3050005, "The producer is not part of current schedule" );
FC_DECLARE_DERIVED_EXCEPTION( snapshot_directory_not_found_exception,  producer_exception, 3050006, "The configured snapshot directory does not exist" );
FC_DECLARE_DERIVED_EXCEPTION( snapshot_exists_exception,               producer_exception, 3050007, "The requested snapshot already exists" );

FC_DECLARE_DERIVED_EXCEPTION( block_log_exception,           chain_exception,     3060000, "Block log exception" );
FC_DECLARE_DERIVED_EXCEPTION( block_log_unsupported_version, block_log_exception, 3060001, "unsupported version of block log" );
FC_DECLARE_DERIVED_EXCEPTION( block_log_append_fail,         block_log_exception, 3060002, "fail to append block to the block log" );
FC_DECLARE_DERIVED_EXCEPTION( block_log_not_found,           block_log_exception, 3060003, "block log can not be found" );
FC_DECLARE_DERIVED_EXCEPTION( block_log_backup_dir_exist,    block_log_exception, 3060004, "block log backup dir already exists" );

FC_DECLARE_DERIVED_EXCEPTION( fork_database_exception, chain_exception,         3080000, "Fork database exception" );
FC_DECLARE_DERIVED_EXCEPTION( fork_db_block_not_found, fork_database_exception, 3080001, "Block can not be found" );

FC_DECLARE_DERIVED_EXCEPTION( reversible_blocks_exception,        chain_exception,             3090000, "Reversible Blocks exception" );
FC_DECLARE_DERIVED_EXCEPTION( invalid_reversible_blocks_dir,      reversible_blocks_exception, 3090001, "Invalid reversible blocks directory" );
FC_DECLARE_DERIVED_EXCEPTION( reversible_blocks_backup_dir_exist, reversible_blocks_exception, 3090002, "Backup directory for reversible blocks already existg" );
FC_DECLARE_DERIVED_EXCEPTION( gap_in_reversible_blocks_db,        reversible_blocks_exception, 3090003, "Gap in the reversible blocks database" );

FC_DECLARE_DERIVED_EXCEPTION( misc_exception,                  chain_exception, 3100000, "Miscellaneous exception");
FC_DECLARE_DERIVED_EXCEPTION( unknown_block_exception,         misc_exception,  3100002, "unknown block" );
FC_DECLARE_DERIVED_EXCEPTION( unknown_transaction_exception,   misc_exception,  3100003, "unknown transaction" );
FC_DECLARE_DERIVED_EXCEPTION( fixed_reversible_db_exception,   misc_exception,  3100004, "Corrupted reversible block database was fixed." );
FC_DECLARE_DERIVED_EXCEPTION( extract_genesis_state_exception, misc_exception,  3100005, "extracted genesis state from blocks.log" );
FC_DECLARE_DERIVED_EXCEPTION( unsupported_feature,             misc_exception,  3100006, "Feature is currently unsupported" );
FC_DECLARE_DERIVED_EXCEPTION( node_management_success,         misc_exception,  3100007, "Node management operation successfully executed" );

FC_DECLARE_DERIVED_EXCEPTION( authorization_exception,   chain_exception,         3110000, "Authorization exception");
FC_DECLARE_DERIVED_EXCEPTION( tx_duplicate_sig,          authorization_exception, 3110001, "Duplicate signature is included." );
FC_DECLARE_DERIVED_EXCEPTION( tx_irrelevant_sig,         authorization_exception, 3110002, "Irrelevant signature is included." );
FC_DECLARE_DERIVED_EXCEPTION( unsatisfied_authorization, authorization_exception, 3110003, "Provided keys do not satisfy declared authorizations." );

FC_DECLARE_DERIVED_EXCEPTION( chain_type_exception,              chain_exception,      3120000, "chain type exception" );
FC_DECLARE_DERIVED_EXCEPTION( name_type_exception,               chain_type_exception, 3120001, "Invalid name" );
FC_DECLARE_DERIVED_EXCEPTION( public_key_type_exception,         chain_type_exception, 3120002, "Invalid public key" );
FC_DECLARE_DERIVED_EXCEPTION( private_key_type_exception,        chain_type_exception, 3120003, "Invalid private key" );
FC_DECLARE_DERIVED_EXCEPTION( authority_type_exception,          chain_type_exception, 3120004, "Invalid authority" );
FC_DECLARE_DERIVED_EXCEPTION( action_type_exception,             chain_type_exception, 3120005, "Invalid action" );
FC_DECLARE_DERIVED_EXCEPTION( transaction_type_exception,        chain_type_exception, 3120006, "Invalid transaction" );
FC_DECLARE_DERIVED_EXCEPTION( abi_type_exception,                chain_type_exception, 3120007, "Invalid ABI" );
FC_DECLARE_DERIVED_EXCEPTION( block_id_type_exception,           chain_type_exception, 3120009, "Invalid block ID" );
FC_DECLARE_DERIVED_EXCEPTION( transaction_id_type_exception,     chain_type_exception, 3120010, "Invalid transaction ID" );
FC_DECLARE_DERIVED_EXCEPTION( packed_transaction_type_exception, chain_type_exception, 3120011, "Invalid packed transaction" );
FC_DECLARE_DERIVED_EXCEPTION( asset_type_exception,              chain_type_exception, 3120012, "Invalid asset" );
FC_DECLARE_DERIVED_EXCEPTION( symbol_type_exception,             chain_type_exception, 3120013, "Invalid symbol" );
FC_DECLARE_DERIVED_EXCEPTION( permission_type_exception,         chain_type_exception, 3120014, "Invalid permission" );
FC_DECLARE_DERIVED_EXCEPTION( group_type_exception,              chain_type_exception, 3120015, "Invalid group" );
FC_DECLARE_DERIVED_EXCEPTION( authorizer_ref_type_exception,     chain_type_exception, 3120016, "Invalid authorizer ref" );
FC_DECLARE_DERIVED_EXCEPTION( address_type_exception,            chain_type_exception, 3120017, "Invalid address" );
FC_DECLARE_DERIVED_EXCEPTION( name128_type_exception,            chain_type_exception, 3120018, "Invalid name128" );
FC_DECLARE_DERIVED_EXCEPTION( chain_id_type_exception,           chain_type_exception, 3120019, "Invalid chain id" );
FC_DECLARE_DERIVED_EXCEPTION( variant_type_exception,            chain_type_exception, 3120019, "Invalid variant" );
FC_DECLARE_DERIVED_EXCEPTION( percent_type_exception,            chain_type_exception, 3120020, "Invalid percent value" );

FC_DECLARE_DERIVED_EXCEPTION( plugin_exception,                      chain_exception,  3130000, "plugin exception" );
FC_DECLARE_DERIVED_EXCEPTION( missing_chain_api_plugin_exception,    plugin_exception, 3130001, "Missing Chain API Plugin" );
FC_DECLARE_DERIVED_EXCEPTION( missing_wallet_api_plugin_exception,   plugin_exception, 3130002, "Missing Wallet API Plugin" );
FC_DECLARE_DERIVED_EXCEPTION( missing_net_api_plugin_exception,      plugin_exception, 3130003, "Missing Net API Plugin" );
FC_DECLARE_DERIVED_EXCEPTION( missing_evt_api_plugin_exception,      plugin_exception, 3130004, "Missing EVT API Plugin" );
FC_DECLARE_DERIVED_EXCEPTION( missing_history_api_plugin_exception,  plugin_exception, 3130005, "Missing History API Plugin" );
FC_DECLARE_DERIVED_EXCEPTION( plugin_config_exception,               plugin_exception, 3130006, "Incorrect plugin configuration" );
FC_DECLARE_DERIVED_EXCEPTION( missing_chain_plugin_exception,        plugin_exception, 3130008, "Missing Chain Plugin" );
FC_DECLARE_DERIVED_EXCEPTION( missing_producer_api_plugin_exception, plugin_exception, 3130009, "Missing Producer API Plugin" );
FC_DECLARE_DERIVED_EXCEPTION( missing_postgres_plugin_exception,     plugin_exception, 3130010, "Missing postgres Plugin" );
FC_DECLARE_DERIVED_EXCEPTION( exceed_query_limit_exception,          plugin_exception, 3130011, "Exceed max query limit" );

FC_DECLARE_DERIVED_EXCEPTION( wallet_exception,                  chain_exception,  3140000, "wallet exception" );
FC_DECLARE_DERIVED_EXCEPTION( wallet_exist_exception,            wallet_exception, 3140001, "Wallet already exists" );
FC_DECLARE_DERIVED_EXCEPTION( wallet_nonexistent_exception,      wallet_exception, 3140002, "Nonexistent wallet" );
FC_DECLARE_DERIVED_EXCEPTION( wallet_locked_exception,           wallet_exception, 3140003, "Locked wallet" );
FC_DECLARE_DERIVED_EXCEPTION( wallet_missing_pub_key_exception,  wallet_exception, 3140004, "Missing public key" );
FC_DECLARE_DERIVED_EXCEPTION( wallet_invalid_password_exception, wallet_exception, 3140005, "Invalid wallet password" );
FC_DECLARE_DERIVED_EXCEPTION( wallet_not_available_exception,    wallet_exception, 3140006, "No available wallet" );
FC_DECLARE_DERIVED_EXCEPTION( wallet_unlocked_exception,         wallet_exception, 3140007, "Already unlocked" );
FC_DECLARE_DERIVED_EXCEPTION( key_exist_exception,               wallet_exception, 3140008, "Key already exists" );
FC_DECLARE_DERIVED_EXCEPTION( key_nonexistent_exception,         wallet_exception, 3140009, "Nonexistent key" );
FC_DECLARE_DERIVED_EXCEPTION( unsupported_key_type_exception,    wallet_exception, 3140010, "Unsupported key type" );
FC_DECLARE_DERIVED_EXCEPTION( invalid_lock_timeout_exception,    wallet_exception, 3140011, "Wallet lock timeout is invalid" );
FC_DECLARE_DERIVED_EXCEPTION( secure_enclave_exception,          wallet_exception, 3140012, "Secure Enclave Exception" );

FC_DECLARE_DERIVED_EXCEPTION( token_database_exception,            chain_exception,          3150000, "token_database exception" );
FC_DECLARE_DERIVED_EXCEPTION( token_database_dupe_key,             token_database_exception, 3150001, "Duplicate key in token database." );
FC_DECLARE_DERIVED_EXCEPTION( unknown_token_database_key,          token_database_exception, 3150002, "Unknown key in token database." );
FC_DECLARE_DERIVED_EXCEPTION( token_database_rocksdb_exception,    token_database_exception, 3150003, "Rocksdb internal error occurred." );
FC_DECLARE_DERIVED_EXCEPTION( token_database_no_savepoint,         token_database_exception, 3150004, "No savepoints anymore" );
FC_DECLARE_DERIVED_EXCEPTION( token_database_seq_not_valid,        token_database_exception, 3150005, "Seq for checkpoint is not valid." );
FC_DECLARE_DERIVED_EXCEPTION( token_database_db_action_exception,  token_database_exception, 3150006, "Unknown db action type." );
FC_DECLARE_DERIVED_EXCEPTION( token_database_dirty_flag_exception, token_database_exception, 3150007, "Checkspoints log file is in dirty." );
FC_DECLARE_DERIVED_EXCEPTION( token_database_squash_exception,     token_database_exception, 3150008, "Cannot perform squash operation now" );
FC_DECLARE_DERIVED_EXCEPTION( token_database_snapshot_exception,   token_database_exception, 3150009, "Create or restore snapshot failed" );
FC_DECLARE_DERIVED_EXCEPTION( token_database_persist_exception,    token_database_exception, 3150010, "Persist savepoints failed" );
FC_DECLARE_DERIVED_EXCEPTION( token_database_cache_exception,      token_database_exception, 3150010, "Invalid cache entry" );

FC_DECLARE_DERIVED_EXCEPTION( guard_exception,            database_exception, 3160101, "Database exception" );
FC_DECLARE_DERIVED_EXCEPTION( database_guard_exception,   guard_exception,    3160102, "Database usage is at unsafe levels" );
FC_DECLARE_DERIVED_EXCEPTION( reversible_guard_exception, guard_exception,    3160103, "Reversible block log usage is at unsafe levels" );

FC_DECLARE_DERIVED_EXCEPTION( controller_emit_signal_exception, chain_exception, 3170000, "Exceptions that are allowed to bubble out of emit calls in controller" );
FC_DECLARE_DERIVED_EXCEPTION( checkpoint_exception,             controller_emit_signal_exception, 3170001, "Block does not match checkpoint" );

FC_DECLARE_DERIVED_EXCEPTION( http_exception,                chain_exception, 3180000, "http exception" );
FC_DECLARE_DERIVED_EXCEPTION( invalid_http_client_root_cert, http_exception,  3180001, "invalid http client root certificate" );
FC_DECLARE_DERIVED_EXCEPTION( invalid_http_response,         http_exception,  3180002, "invalid http response" );
FC_DECLARE_DERIVED_EXCEPTION( resolved_to_multiple_ports,    http_exception,  3180003, "service resolved to multiple ports" );
FC_DECLARE_DERIVED_EXCEPTION( fail_to_resolve_host,          http_exception,  3180004, "fail to resolve host" );
FC_DECLARE_DERIVED_EXCEPTION( http_request_fail,             http_exception,  3180005, "http request fail" );
FC_DECLARE_DERIVED_EXCEPTION( invalid_http_request,          http_exception,  3180006, "invalid http request" );
FC_DECLARE_DERIVED_EXCEPTION( exceed_deferred_request,       http_exception,  3180007, "exceed max http deferred request" );
FC_DECLARE_DERIVED_EXCEPTION( alloc_deferred_fail,           http_exception,  3180008, "Failed to alloc deferred id" );

FC_DECLARE_DERIVED_EXCEPTION( evt_link_plugin_exception,            chain_exception, 3190000, "evt-link plugin exception" );
FC_DECLARE_DERIVED_EXCEPTION( evt_link_not_existed_now_excetpion,   evt_link_plugin_exception, 3190001, "EVT-Link is not existed currently" );
FC_DECLARE_DERIVED_EXCEPTION( evt_link_already_watched_exception,   evt_link_plugin_exception, 3190002, "EVT-Link is already watched" );
FC_DECLARE_DERIVED_EXCEPTION( exceed_evt_link_watch_time_exception, evt_link_plugin_exception, 3190003, "Exceed EVT-Link watch time" );

FC_DECLARE_DERIVED_EXCEPTION( resource_exhausted_exception, chain_exception, 3200000, "Resource exhausted exception" );
FC_DECLARE_DERIVED_EXCEPTION( tx_net_usage_exceeded,        resource_exhausted_exception, 3200001, "Transaction exceeded the current network usage limit imposed on the transaction" );
FC_DECLARE_DERIVED_EXCEPTION( block_net_usage_exceeded,     resource_exhausted_exception, 3200002, "Transaction network usage is too much for the remaining allowable usage of the current block" );

FC_DECLARE_DERIVED_EXCEPTION( abi_exception,                        chain_exception, 3210000, "ABI exception" );
FC_DECLARE_DERIVED_EXCEPTION( abi_not_found_exception,              abi_exception,   3210001, "No ABI found" );
FC_DECLARE_DERIVED_EXCEPTION( invalid_ricardian_clause_exception,   abi_exception,   3210002, "Invalid Ricardian Clause" );
FC_DECLARE_DERIVED_EXCEPTION( invalid_ricardian_action_exception,   abi_exception,   3210003, "Invalid Ricardian Action" );
FC_DECLARE_DERIVED_EXCEPTION( invalid_type_inside_abi,              abi_exception,   3210004, "The type defined in the ABI is invalid" ); // Not to be confused with abi_type_exception
FC_DECLARE_DERIVED_EXCEPTION( duplicate_abi_type_def_exception,     abi_exception,   3210005, "Duplicate type definition in the ABI" );
FC_DECLARE_DERIVED_EXCEPTION( duplicate_abi_struct_def_exception,   abi_exception,   3210006, "Duplicate struct definition in the ABI" );
FC_DECLARE_DERIVED_EXCEPTION( duplicate_abi_action_def_exception,   abi_exception,   3210007, "Duplicate action definition in the ABI" );
FC_DECLARE_DERIVED_EXCEPTION( duplicate_abi_variant_def_exception,  abi_exception,   3210008, "Duplicate variant definition in the ABI" );
FC_DECLARE_DERIVED_EXCEPTION( duplicate_abi_enum_def_exception,     abi_exception,   3210009, "Duplicate enum definition in the ABI" );
FC_DECLARE_DERIVED_EXCEPTION( duplicate_abi_err_msg_def_exception,  abi_exception,   3210010, "Duplicate error message definition in the ABI" );
FC_DECLARE_DERIVED_EXCEPTION( abi_serialization_deadline_exception, abi_exception,   3210011, "ABI serialization time has exceeded the deadline" );
FC_DECLARE_DERIVED_EXCEPTION( abi_recursion_depth_exception,        abi_exception,   3210012, "ABI recursive definition has exceeded the max recursion depth" );
FC_DECLARE_DERIVED_EXCEPTION( abi_circular_def_exception,           abi_exception,   3210013, "Circular definition is detected in the ABI" );
FC_DECLARE_DERIVED_EXCEPTION( unpack_exception,                     abi_exception,   3210014, "Unpack data exception" );
FC_DECLARE_DERIVED_EXCEPTION( pack_exception,                       abi_exception,   3210015, "Pack data exception" );
FC_DECLARE_DERIVED_EXCEPTION( unsupported_abi_version_exception,    abi_exception,   3210016, "ABI has an unsupported version" );
FC_DECLARE_DERIVED_EXCEPTION( unknown_abi_type_exception,           abi_exception,   3210017, "Unknown type in ABI" );

FC_DECLARE_DERIVED_EXCEPTION( snapshot_exception, chain_exception, 3220000, "Snapshot exception" );
FC_DECLARE_DERIVED_EXCEPTION( snapshot_validation_exception, snapshot_exception, 3220001, "Snapshot Validation Exception" );

FC_DECLARE_DERIVED_EXCEPTION( postgres_plugin_exception,      chain_exception,           3230000, "Postgres plugin exception" );
FC_DECLARE_DERIVED_EXCEPTION( postgres_connection_exception,  postgres_plugin_exception, 3230001, "Connect to postgresql server failed" );
FC_DECLARE_DERIVED_EXCEPTION( postgres_exec_exception,        postgres_plugin_exception, 3230002, "Execute statements failed" );
FC_DECLARE_DERIVED_EXCEPTION( postgres_version_exception,     postgres_plugin_exception, 3230003, "Version of postgres database is obsolete" );
FC_DECLARE_DERIVED_EXCEPTION( postgres_sync_exception,        postgres_plugin_exception, 3230004, "Sync failed between postgres database and current blockchain state" );
FC_DECLARE_DERIVED_EXCEPTION( postgres_send_exception,        postgres_plugin_exception, 3230005, "Send commands to postgres failed" );
FC_DECLARE_DERIVED_EXCEPTION( postgres_poll_exception,        postgres_plugin_exception, 3230006, "Poll messages from postgres failed" );
FC_DECLARE_DERIVED_EXCEPTION( postgres_query_exception,       postgres_plugin_exception, 3230007, "Query from postgres failed" );
FC_DECLARE_DERIVED_EXCEPTION( postgres_not_enabled_exception, postgres_plugin_exception, 3230008, "Postgres plugin is not enabled" );

FC_DECLARE_DERIVED_EXCEPTION( execution_exception,      chain_exception,     3240000, "Execution exception" );
FC_DECLARE_DERIVED_EXCEPTION( unknown_action_exception, execution_exception, 3240001, "Unknown action exception" );
FC_DECLARE_DERIVED_EXCEPTION( action_index_exception,   execution_exception, 3240002, "Invalid action index exception" );
FC_DECLARE_DERIVED_EXCEPTION( action_version_exception, execution_exception, 3240003, "Invalid action version exception" );

FC_DECLARE_DERIVED_EXCEPTION( confirm_plugin_exception,      chain_exception, 3250000, "Confirm plugin exception" );
FC_DECLARE_DERIVED_EXCEPTION( invalid_transaction_exception, chain_exception, 3250001, "Invalid transaction to confirm" );
FC_DECLARE_DERIVED_EXCEPTION( invalid_rounds_exception,      chain_exception, 3250002, "Invalid rounds to confirm" );

}} // evt::chain
