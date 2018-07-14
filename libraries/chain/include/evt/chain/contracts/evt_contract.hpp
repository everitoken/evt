/**
 *  @file
 *  @copyright defined in evt/LICENSE.txt
 */
#pragma once

#include <evt/chain/version.hpp>

namespace evt { namespace chain {
class apply_context;
}}  // namespace evt::chain

namespace evt { namespace chain { namespace contracts {

struct abi_def;

/**
* @defgroup native_action_handlers Native Action Handlers
*/
///@{

void apply_evt_newdomain(apply_context& context);
void apply_evt_issuetoken(apply_context& context);
void apply_evt_transfer(apply_context& context);
void apply_evt_destroytoken(apply_context& context);
void apply_evt_newgroup(apply_context& context);
void apply_evt_updategroup(apply_context& context);
void apply_evt_updatedomain(apply_context& context);

void apply_evt_newfungible(apply_context& context);
void apply_evt_updfungible(apply_context& context);
void apply_evt_issuefungible(apply_context& context);
void apply_evt_transferft(apply_context& context);
void apply_evt_evt2pevt(apply_context& context);

void apply_evt_addmeta(apply_context& context);

void apply_evt_newsuspend(apply_context& context);
void apply_evt_aprvsuspend(apply_context& context);
void apply_evt_cancelsuspend(apply_context& context);
void apply_evt_execsuspend(apply_context& context);

abi_def evt_contract_abi();
version evt_contract_abi_version();

///@}  end action handlers

}}}  // namespace evt::chain::contracts
