/**
 *  @file
 *  @copyright defined in evt/LICENSE.txt
 */
#pragma once

#include <algorithm>
#include <array>
#include <functional>
#include <string>
#include <type_traits>

#include <boost/hana.hpp>

#include <evt/chain/execution_context.hpp>
#include <evt/chain/exceptions.hpp>
#include <evt/chain/types.hpp>
#include <evt/chain/contracts/types.hpp>

namespace hana = boost::hana;

namespace evt { namespace chain {

template<typename ... ACTTYPE>
class execution_context_impl : public execution_context {
public:
    execution_context_impl()
        : curr_vers_() {
        constexpr auto index_of = [](auto& act) {
            return hana::index_if(act_names_, hana::equal.to(hana::ulong_c<decltype(+act)::type::get_action_name().value>)).value();
        };

        auto act_types = hana::sort.by(hana::ordering([](auto& act) { return hana::int_c<decltype(+act)::type::get_version()>; }), act_types_);
        hana::for_each(act_types, [&](auto& act) {
            auto i = index_of(act);
            type_names_[i].emplace_back(decltype(+act)::type::get_type_name());
            assert(type_names_[i].size() == decltype(+act)::type::get_version());
            curr_vers_[i] = 1;  // ver starts from 1
        });

        act_names_arr_ = hana::unpack(act_names_, [](auto ...i) {
            return std::array<uint64_t, sizeof...(i)>{{i...}};
        });
    }

    ~execution_context_impl() override {}

public:
    int
    index_of(name act) const override {
        auto& arr = act_names_arr_;
        auto it   = std::lower_bound(std::cbegin(arr), std::cend(arr), act.value);
        EVT_ASSERT(it != std::cend(arr) && *it == act.value, unknown_action_exception, "Unknown action: ${act}", ("act", act));

        return std::distance(std::cbegin(arr), it);
    }

    template<typename T>
    constexpr int
    index_of() const {
        auto i = hana::index_if(act_names_, hana::equal.to(hana::ulong_c<T::get_action_name().value>));
        static_assert(i != hana::nothing, "T is not valid action type");

        return i.value()();
    }

    int
    set_version(name act, int newver) override {
        auto actindex = index_of(act);
        auto cver     = curr_vers_[actindex];
        auto mver     = type_names_[actindex].size();

        EVT_ASSERT2(newver > cver && newver <= (int)mver, action_version_exception, "New version should be in range ({},{}]", cver, mver);

        auto old_ver         = cver;
        curr_vers_[actindex] = newver;

        return old_ver;
    }

    int
    set_version_unsafe(name act, int newver) override {
        auto actindex = index_of(act);
        auto cver     = curr_vers_[actindex];
        auto mver     = type_names_[actindex].size() - 1;

        auto old_ver         = cver;
        curr_vers_[actindex] = newver;

        return old_ver;
    }

    std::string
    get_acttype_name(name act) const override {
        auto index = index_of(act);
        return type_names_[index][get_curr_ver(index) - 1];
    }

    int
    get_current_version(name act) const override {
        return get_curr_ver(index_of(act));
    }

    int
    get_max_version(name act) const override {
        return (int)type_names_[index_of(act)].size();
    }

    template <template<uint64_t> typename Invoker, typename RType, typename ... Args>
    RType
    invoke(int actindex, Args&&... args) const {
        using opt_type = std::conditional_t<std::is_void<RType>::value, int, RType>;

        auto fn = [&](auto i) -> std::optional<opt_type> {
            auto name  = act_names_[i];
            auto vers  = hana::filter(act_types_,
                [&](auto& t) { return hana::equal(name, hana::ulong_c<decltype(+t)::type::get_action_name().value>); });
            auto cver = curr_vers_[i];

            static_assert(hana::length(vers)() > hana::size_c<0>(), "empty version actions!");

            auto result = std::optional<opt_type>();
            hana::for_each(vers, [&, cver](auto v) {
                using ty = typename decltype(+v)::type;

                constexpr auto n = ty::get_action_name().value;
                if(ty::get_version() == cver) {
                    if constexpr (std::is_void<RType>::value) {
                        Invoker<n>::template invoke<ty>(std::forward<Args>(args)...);
                        result = 1;
                    }
                    else {
                        result = Invoker<n>::template invoke<ty>(std::forward<Args>(args)...);
                    }
                }
            });

            return result;
        };

        auto range  = hana::make_range(hana::int_c<0>, hana::length(act_names_));
        auto result = std::optional<opt_type>();
        hana::for_each(range, [&](auto i) {
            if(i() == actindex) {
                result = fn(i);
            }
        });

        EVT_ASSERT(result.has_value(), action_index_exception, "Invalid action index: ${act}", ("act", actindex));
        if constexpr (!std::is_void<RType>::value) {
            return *result;
        }
    }

    template <typename T, typename Func>
    void
    invoke_action(const action& act, Func&& func) const {
        auto i = hana::index_if(act_names_, hana::equal.to(hana::ulong_c<T::get_action_name().value>));
        static_assert(i != hana::nothing, "T is not valid action type");

        auto name  = act_names_[i.value()];
        auto vers  = hana::filter(act_types_,
            [&](auto& t) { return hana::equal(name, hana::ulong_c<decltype(+t)::type::get_action_name().value>); });
        auto cver = curr_vers_[i.value()];

        static_assert(hana::length(vers)() > hana::size_c<0>(), "empty version actions!");

        hana::for_each(vers, [&, cver](auto v) {
            using ty = typename decltype(+v)::type;
            if(ty::get_version() == cver) {
                func(act.data_as<const ty&>());
            }
        });
    }

    std::vector<action_ver>
    get_current_actions() const override {
        auto acts = std::vector<action_ver>();
        acts.reserve(act_names_arr_.size());
        
        for(auto i = 0u; i < act_names_arr_.size(); i++) {
            acts.emplace_back(action_ver {
                .act  = name(act_names_arr_[i]),
                .ver  = curr_vers_[i],
                .type = type_names_[i][curr_vers_[i]]
            });
        }

        return acts;
    }

private:
    int
    get_curr_ver(int index) const {
        return curr_vers_[index];
    }

private:
    static constexpr auto act_types_ = hana::make_tuple(hana::type_c<ACTTYPE>...);
    static constexpr auto act_names_ = hana::sort(hana::unique(hana::transform(act_types_, [](auto& a) { return hana::ulong_c<decltype(+a)::type::get_action_name().value>; })));

private:
    std::array<int, hana::length(act_names_)>                          curr_vers_;
    std::array<uint64_t, hana::length(act_names_)>                     act_names_arr_;
    std::array<small_vector<std::string, 4>, hana::length(act_names_)> type_names_;
};

using evt_execution_context = execution_context_impl<
                                  contracts::newdomain,
                                  contracts::updatedomain,
                                  contracts::issuetoken,
                                  contracts::transfer,
                                  contracts::destroytoken,
                                  contracts::newgroup,
                                  contracts::updategroup,
                                  contracts::newfungible,
                                  contracts::newfungible_v2,
                                  contracts::updfungible,
                                  contracts::updfungible_v2,
                                  contracts::issuefungible,
                                  contracts::transferft,
                                  contracts::recycleft,
                                  contracts::destroyft,
                                  contracts::evt2pevt,
                                  contracts::addmeta,
                                  contracts::newsuspend,
                                  contracts::cancelsuspend,
                                  contracts::aprvsuspend,
                                  contracts::execsuspend,
                                  contracts::paycharge,
                                  contracts::paybonus,
                                  contracts::everipass,
                                  contracts::everipass_v2,
                                  contracts::everipay,
                                  contracts::everipay_v2,
                                  contracts::prodvote,
                                  contracts::updsched,
                                  contracts::newlock,
                                  contracts::aprvlock,
                                  contracts::tryunlock,
                                  contracts::setpsvbonus,
                                  contracts::setpsvbonus_v2,
                                  contracts::distpsvbonus
                              >;

}}  // namespace evt::chain
