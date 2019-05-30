/**
 *  @file
 *  @copyright defined in evt/LICENSE.txt
 */
#pragma once
#include <chrono>

#include <boost/noncopyable.hpp>
#include <fc/variant_object.hpp>
#include <fc/scoped_exit.hpp>

#include <evt/chain/config.hpp>
#include <evt/chain/exceptions.hpp>
#include <evt/chain/execution_context.hpp>
#include <evt/chain/trace.hpp>
#include <evt/chain/contracts/abi_types.hpp>
#include <evt/chain/contracts/types.hpp>

namespace evt { namespace chain { namespace contracts {

using namespace fc;

namespace impl {
struct abi_from_variant;
struct abi_to_variant;

struct abi_traverse_context;
struct abi_traverse_context_with_path;
struct binary_to_variant_context;
struct variant_to_binary_context;
}  // namespace impl

/**
 *  Describes the binary representation message and table contents so that it can
 *  be converted to and from JSON.
 */
struct abi_serializer : boost::noncopyable {
    abi_serializer() { configure_built_in_types(); }
    abi_serializer(const abi_def& abi, const std::chrono::microseconds max_serialization_time);
    void set_abi(const abi_def& abi);

    type_name resolve_type(const type_name& t) const;
    type_name fundamental_type(const type_name& type) const;

    bool is_array(const type_name& type) const;
    bool is_optional(const type_name& type) const;
    bool is_type(const type_name& type) const;
    bool is_builtin_type(const type_name& type) const;
    bool is_integer(const type_name& type) const;
    bool is_struct(const type_name& type) const;
    bool is_variant(const type_name& type) const;
    bool is_enum(const type_name& type) const;

    int get_integer_size(const type_name& type) const;

    const struct_def& get_struct(const type_name& type) const;

    optional<string> get_error_message(uint64_t error_code) const;

    fc::variant binary_to_variant(const type_name& type, const bytes& binary, const execution_context&, bool short_path = false) const;
    fc::variant binary_to_variant(const type_name& type, fc::datastream<const char*>& binary, const execution_context&, bool short_path = false) const;

    bytes variant_to_binary(const type_name& type, const fc::variant& var, const execution_context&,  bool short_path = false) const;
    void  variant_to_binary(const type_name& type, const fc::variant& var, fc::datastream<char*>& ds, const execution_context&, bool short_path = false) const;

    template <typename T>
    void to_variant(const T& o, fc::variant& vo, const execution_context&) const;

    template <typename T>
    void from_variant(const fc::variant& v, T& o, const execution_context&) const;

    template <typename Vec>
    static bool
    is_empty_abi(const Vec& abi_vec) {
        return abi_vec.size() <= 4;
    }

    template <typename Vec>
    static bool
    to_abi(const Vec& abi_vec, abi_def& abi) {
        if(!is_empty_abi(abi_vec)) {  /// 4 == packsize of empty Abi
            fc::datastream<const char*> ds(abi_vec.data(), abi_vec.size());
            fc::raw::unpack(ds, abi);
            return true;
        }
        return false;
    }

    typedef std::function<fc::variant(fc::datastream<const char*>&, bool, bool)>        unpack_function;
    typedef std::function<void(const fc::variant&, fc::datastream<char*>&, bool, bool)> pack_function;

    void add_specialized_unpack_pack(const string& name, std::pair<abi_serializer::unpack_function, abi_serializer::pack_function> unpack_pack);

    static const size_t max_recursion_depth = 32;  // arbitrary depth to prevent infinite recursion

private:  
    void configure_built_in_types();

    fc::variant _binary_to_variant(const type_name& type, const bytes& binary, impl::binary_to_variant_context& ctx) const;
    fc::variant _binary_to_variant(const type_name& type, fc::datastream<const char*>& binary, impl::binary_to_variant_context& ctx) const;
    void        _binary_to_variant(const type_name& type, fc::datastream<const char*>& stream,
                                   fc::mutable_variant_object& obj, impl::binary_to_variant_context& ctx) const;

    bytes _variant_to_binary(const type_name& type, const fc::variant& var, impl::variant_to_binary_context& ctx) const;
    void  _variant_to_binary(const type_name& type, const fc::variant& var,
                             fc::datastream<char*>& ds, impl::variant_to_binary_context& ctx) const;

    bool _is_type(const type_name& type) const;

    void validate() const;

private:
    std::map<type_name, type_name>   typedefs_;
    std::map<type_name, struct_def>  structs_;
    std::map<type_name, variant_def> variants_;
    std::map<type_name, enum_def>    enums_;

    std::map<type_name, pair<unpack_function, pack_function>> built_in_types_;

    std::chrono::microseconds max_serialization_time_;

private:
    friend struct impl::abi_from_variant;
    friend struct impl::abi_to_variant;
    friend struct impl::abi_traverse_context;
    friend struct impl::abi_traverse_context_with_path;
};

namespace impl {

struct abi_traverse_context {
    abi_traverse_context(const abi_serializer& self, const execution_context& exec_ctx)
        : self(self)
        , exec_ctx(exec_ctx)
        , max_serialization_time(self.max_serialization_time_)
        , deadline(std::chrono::steady_clock::now())   // init to now, updated below
        , recursion_depth(0) {
        if(max_serialization_time > std::chrono::steady_clock::time_point::max() - deadline) {
            deadline = std::chrono::steady_clock::time_point::max();
        }
        else {
            deadline += max_serialization_time;
        }
    }

    abi_traverse_context(const abi_serializer& self, const execution_context& exec_ctx, std::chrono::steady_clock::time_point deadline)
        : self(self)
        , exec_ctx(exec_ctx)
        , max_serialization_time(self.max_serialization_time_)
        , deadline(deadline)
        , recursion_depth(0) {}

    void check_deadline() const;

    fc::scoped_exit<std::function<void()>> enter_scope();

public:
    const abi_serializer&    self;
    const execution_context& exec_ctx;

protected:
    std::chrono::microseconds             max_serialization_time;
    std::chrono::steady_clock::time_point deadline;
    size_t                                recursion_depth;
};

struct empty_path_root {};

struct array_type_path_root {
};

struct struct_type_path_root {
    map<type_name, struct_def>::const_iterator itr;
};

struct variant_type_path_root {
    map<type_name, variant_def>::const_iterator itr;
};

struct enum_type_path_root {
    map<type_name, enum_def>::const_iterator itr;
};

using path_root = static_variant<empty_path_root, array_type_path_root, struct_type_path_root, variant_type_path_root, enum_type_path_root>;

struct empty_path_item {};

struct array_index_path_item {
    path_root type_hint;
    uint32_t  array_index = 0;
};

struct field_path_item {
    map<type_name, struct_def>::const_iterator parent_itr;
    uint32_t                                   field_ordinal = 0;
};

struct variant_path_item {
    map<type_name, variant_def>::const_iterator parent_itr;
    uint32_t                                    index = 0;
};

using path_item = static_variant<empty_path_item, array_index_path_item, field_path_item, variant_path_item>;

struct abi_traverse_context_with_path : public abi_traverse_context {
    abi_traverse_context_with_path(const abi_serializer& self, const execution_context& exec_ctx, const type_name& type)
        : abi_traverse_context(self, exec_ctx) {
        set_path_root(type);
    }

    abi_traverse_context_with_path(const abi_serializer& self, const execution_context& exec_ctx, std::chrono::steady_clock::time_point deadline, const type_name& type)
        : abi_traverse_context(self, exec_ctx, deadline) {
        set_path_root(type);
    }

    abi_traverse_context_with_path(const abi_traverse_context& ctx, const type_name& type)
        : abi_traverse_context(ctx) {
        set_path_root(type);
    }

    void set_path_root(const type_name& type);

    fc::scoped_exit<std::function<void()>> push_to_path(const path_item& item);

    void set_array_index_of_path_back(uint32_t i);
    void hint_array_type_if_in_array();
    void hint_struct_type_if_in_array(const map<type_name, struct_def>::const_iterator& itr);
    void hint_variant_type_if_in_array(const map<type_name, variant_def>::const_iterator& itr);
    void hint_enum_type_if_in_array(const map<type_name, enum_def>::const_iterator& itr);

    string get_path_string() const;
    string maybe_shorten(const string& str);

protected:
    path_root                  root_of_path;
    small_vector<path_item, 8> path;

public:
    bool short_path = false;
};

struct binary_to_variant_context : public abi_traverse_context_with_path {
    using abi_traverse_context_with_path::abi_traverse_context_with_path;
};

struct variant_to_binary_context : public abi_traverse_context_with_path {
    using abi_traverse_context_with_path::abi_traverse_context_with_path;
};

/**
 * Determine if a type contains ABI related info, perhaps deeply nested
 * @tparam T - the type to check
 */
template <typename T>
constexpr bool
single_type_requires_abi_v() {
    return std::is_base_of<transaction, T>::value ||
           std::is_same<T, packed_transaction>::value ||
           std::is_same<T, transaction_trace>::value ||
           std::is_same<T, transaction_receipt>::value ||
           std::is_same<T, action_trace>::value ||
           std::is_same<T, signed_transaction>::value ||
           std::is_same<T, signed_block>::value ||
           std::is_same<T, action>::value ||
           std::is_same<T, contracts::suspend_def>::value;
}

/**
 * Basic constexpr for a type, aliases the basic check directly
 * @tparam T - the type to check
 */
template <typename T>
struct type_requires_abi {
    static constexpr bool
    value() {
        return single_type_requires_abi_v<T>();
    }
};

/**
 * specialization that catches common container patterns and checks their contained-type
 * @tparam Container - a templated container type whose first argument is the contained type
 */
template <template <typename...> class Container, typename T, typename... Args>
struct type_requires_abi<Container<T, Args...>> {
    static constexpr bool
    value() {
        return single_type_requires_abi_v<T>();
    }
};

template <typename T>
constexpr bool
type_requires_abi_v() {
    return type_requires_abi<T>::value();
}

/**
 * convenience aliases for creating overload-guards based on whether the type contains ABI related info
 */
template <typename T>
using not_require_abi_t = std::enable_if_t<!type_requires_abi_v<T>(), int>;

template <typename T>
using require_abi_t = std::enable_if_t<type_requires_abi_v<T>(), int>;

struct abi_to_variant {
    /**
     * template which overloads add for types which are not relvant to ABI information
     * and can be degraded to the normal ::to_variant(...) processing
     */
    template <typename M, not_require_abi_t<M> = 1>
    static void
    add(mutable_variant_object& mvo, const char* name, const M& v, abi_traverse_context& ctx) {
        auto h = ctx.enter_scope();
        mvo(name, v);
    }

    /**
     * template which overloads add for types which contain ABI information in their trees
     * for these types we create new ABI aware visitors
     */
    template <typename M, require_abi_t<M> = 1>
    static void add(mutable_variant_object& mvo, const char* name, const M& v, abi_traverse_context& ctx);

    /**
     * template which overloads add for vectors of types which contain ABI information in their trees
     * for these members we call ::add in order to trigger further processing
     */
    template <typename M, require_abi_t<M> = 1>
    static void
    add(mutable_variant_object& mvo, const char* name, const vector<M>& v, abi_traverse_context& ctx) {
        auto h     = ctx.enter_scope();
        auto array = small_vector<variant, 4>();
        array.reserve(v.size());

        for(const auto& iter : v) {
            mutable_variant_object elem_mvo;
            add(elem_mvo, "_", iter, ctx);
            array.emplace_back(std::move(elem_mvo["_"]));
        }
        mvo(name, std::move(array));
    }

    template <typename M, std::size_t N, require_abi_t<M> = 1>
    static void
    add(mutable_variant_object& mvo, const char* name, const small_vector<M,N>& v, abi_traverse_context& ctx) {
        auto h     = ctx.enter_scope();
        auto array = small_vector<variant, 4>();
        array.reserve(v.size());

        for(const auto& iter : v) {
            mutable_variant_object elem_mvo;
            add(elem_mvo, "_", iter, ctx);
            array.emplace_back(std::move(elem_mvo["_"]));
        }
        mvo(name, std::move(array));
    }

    /**
     * template which overloads add for shared_ptr of types which contain ABI information in their trees
     * for these members we call ::add in order to trigger further processing
     */
    template <typename M, require_abi_t<M> = 1>
    static void
    add(mutable_variant_object& mvo, const char* name, const std::shared_ptr<M>& v, abi_traverse_context& ctx) {
        auto h = ctx.enter_scope();
        if(!v)
            return;
        mutable_variant_object obj_mvo;
        add(obj_mvo, "_", *v, ctx);
        mvo(name, std::move(obj_mvo["_"]));
    }

    struct add_static_variant {
        mutable_variant_object& obj_mvo;
        abi_traverse_context&   ctx;

        add_static_variant(mutable_variant_object& o, abi_traverse_context& ctx)
            : obj_mvo(o)
            , ctx(ctx) {}

        typedef void result_type;
        template <typename T>
        void
        operator()(T& v) const {
            add(obj_mvo, "_", v, ctx);
        }
    };

    template <typename... Args>
    static void
    add(mutable_variant_object& mvo, const char* name, const fc::static_variant<Args...>& v, abi_traverse_context& ctx) {
        auto h       = ctx.enter_scope();
        auto obj_mvo = mutable_variant_object();
        add_static_variant adder(obj_mvo, ctx);
        v.visit(adder);
        mvo(name, std::move(obj_mvo["_"]));
    }

    /**
     * overload of to_variant_object for actions
     * @param act
     * @return
     */
    static void
    add(mutable_variant_object& out, const char* name, const action& act, abi_traverse_context& ctx) {
        auto h   = ctx.enter_scope();
        auto mvo = mutable_variant_object();
        mvo("name", act.name);
        mvo("domain", act.domain);
        mvo("key", act.key);

        const auto& self = ctx.self;
        auto        type = ctx.exec_ctx.get_acttype_name(act.name);
        if(!type.empty()) {
            try {
                binary_to_variant_context _ctx(ctx, type);
                _ctx.short_path = true;  // Just to be safe while avoiding the complexity of threading an override boolean all over the place
                mvo("data", self._binary_to_variant(type, act.data, _ctx));
                mvo("hex_data", act.data);
            }
            catch(...) {
                // any failure to serialize data, then leave as not serailzed
                mvo("data", act.data);
            }
        }
        else {
            mvo("data", act.data);
        }
        out(name, std::move(mvo));
    }

    /**
     * overload of to_variant_object for packed_transaction
     * @param act
     * @return
     */
    static void
    add(mutable_variant_object& out, const char* name, const packed_transaction& ptrx, abi_traverse_context& ctx) {
        auto h   = ctx.enter_scope();
        auto mvo = mutable_variant_object();
        auto trx = ptrx.get_transaction();
        mvo("id", trx.id());
        mvo("signatures", ptrx.get_signatures());
        mvo("compression", ptrx.get_compression());
        mvo("packed_trx", ptrx.get_packed_transaction());
        add(mvo, "transaction", trx, ctx);

        out(name, std::move(mvo));
    }
};

template <typename T>
class abi_to_variant_visitor {
public:
    abi_to_variant_visitor(mutable_variant_object& _mvo, const T& _val, abi_traverse_context& _ctx)
        : _vo(_mvo)
        , _val(_val)
        , _ctx(_ctx) {}

    /**
     * Visit a single member and add it to the variant object
     * @tparam Member - the member to visit
     * @tparam Class - the class we are traversing
     * @tparam member - pointer to the member
     * @param name - the name of the member
     */
    template <typename Member, class Class, Member(Class::*member)>
    void
    operator()(const char* name) const {
        abi_to_variant::add(_vo, name, (_val.*member), _ctx);
    }

private:
    mutable_variant_object& _vo;
    const T&                _val;
    abi_traverse_context&   _ctx;
};

struct abi_from_variant {
    /**
     * template which overloads extract for types which are not relvant to ABI information
     * and can be degraded to the normal ::from_variant(...) processing
     */
    template <typename M, not_require_abi_t<M> = 1>
    static void
    extract(const variant& v, M& o, abi_traverse_context& ctx) {
        auto h = ctx.enter_scope();
        from_variant(v, o);
    }

    /**
     * template which overloads extract for types which contain ABI information in their trees
     * for these types we create new ABI aware visitors
     */
    template <typename M, require_abi_t<M> = 1>
    static void extract(const variant& v, M& o, abi_traverse_context& ctx);

    /**
     * template which overloads extract for vectors of types which contain ABI information in their trees
     * for these members we call ::extract in order to trigger further processing
     */
    template <typename M, require_abi_t<M> = 1>
    static void
    extract(const variant& v, vector<M>& o, abi_traverse_context& ctx) {
        auto        h     = ctx.enter_scope();
        const auto& array = v.get_array();
        o.clear();
        o.reserve(array.size());
        for(auto itr = array.begin(); itr != array.end(); ++itr) {
            M o_iter;
            extract(*itr, o_iter, ctx);
            o.emplace_back(std::move(o_iter));
        }
    }

    template <typename M, std::size_t N, require_abi_t<M> = 1>
    static void
    extract(const variant& v, small_vector<M,N>& o, abi_traverse_context& ctx) {
        auto        h     = ctx.enter_scope();
        const auto& array = v.get_array();
        o.clear();
        o.reserve(array.size());
        for(auto itr = array.begin(); itr != array.end(); ++itr) {
            M o_iter;
            extract(*itr, o_iter, ctx);
            o.emplace_back(std::move(o_iter));
        }
    }

    /**
     * template which overloads extract for shared_ptr of types which contain ABI information in their trees
     * for these members we call ::extract in order to trigger further processing
     */
    template <typename M, require_abi_t<M> = 1>
    static void
    extract(const variant& v, std::shared_ptr<M>& o, abi_traverse_context& ctx) {
        auto        h  = ctx.enter_scope();
        const auto& vo = v.get_object();
        M           obj;

        extract(vo, obj, ctx);
        o = std::make_shared<M>(obj);
    }

    /**
     * Non templated overload that has priority for the action structure
     * this type has members which must be directly translated by the ABI so it is
     * exploded and processed explicitly
     */
    static void
    extract(const variant& v, action& act, abi_traverse_context& ctx) {
        auto        h  = ctx.enter_scope();
        const auto& vo = v.get_object();

        EVT_ASSERT(vo.contains("name"), action_type_exception, "Missing name");
        EVT_ASSERT(vo.contains("domain"), action_type_exception, "Missing domain");
        EVT_ASSERT(vo.contains("key"), action_type_exception, "Missing key");
        from_variant(vo["name"], act.name);
        from_variant(vo["domain"], act.domain);
        from_variant(vo["key"], act.key);

        bool valid_empty_data = false;
        if(vo.contains("data")) {
            const auto& data = vo["data"];
            if(data.is_string()) {
                from_variant(data, act.data);
                valid_empty_data = act.data.empty();
            }
            else if(data.is_object()) {
                const auto& self = ctx.self;
                auto        type = ctx.exec_ctx.get_acttype_name(act.name);
                if(!type.empty()) {
                    auto _ctx = variant_to_binary_context(ctx, type);
                    _ctx.short_path  = true;  // Just to be safe while avoiding the complexity of threading an override boolean all over the place
                    act.data         = self._variant_to_binary(type, data, _ctx);
                    valid_empty_data = act.data.empty();
                }
            }
        }

        if(!valid_empty_data && act.data.empty()) {
            if(vo.contains("hex_data")) {
                const auto& data = vo["hex_data"];
                if(data.is_string()) {
                    from_variant(data, act.data);
                }
            }
        }

        EVT_ASSERT(valid_empty_data || !act.data.empty(), packed_transaction_type_exception,
                   "Failed to deserialize data for ${name}", ("name", act.name));
    }

    static void
    extract(const variant& v, packed_transaction& ptrx, abi_traverse_context& ctx) {
        auto        h  = ctx.enter_scope();
        const auto& vo = v.get_object();
        EVT_ASSERT(vo.contains("signatures"), packed_transaction_type_exception, "Missing signatures");
        EVT_ASSERT(vo.contains("compression"), packed_transaction_type_exception, "Missing compression");

        auto signatures  = signatures_type();
        auto compression = packed_transaction::compression_type();

        from_variant(vo["signatures"], signatures);
        from_variant(vo["compression"], compression);

        if(vo.contains("packed_trx") && vo["packed_trx"].is_string() && !vo["packed_trx"].as_string().empty()) {
            auto packed_trx = bytes();
            from_variant(vo["packed_trx"], packed_trx);

            ptrx = packed_transaction(std::move(packed_trx), std::move(signatures), compression);
        }
        else {
            EVT_ASSERT(vo.contains("transaction"), packed_transaction_type_exception, "Missing transaction");
            
            auto trx = signed_transaction();
            extract(vo["transaction"], trx, ctx);
            trx.signatures = std::move(signatures);

            ptrx = packed_transaction(std::move(trx), compression);
        }
    }
};

template <typename T>
class abi_from_variant_visitor : public reflector_init_visitor<T> {
public:
    abi_from_variant_visitor(const variant_object& _vo, T& v, abi_traverse_context& _ctx)
        : reflector_init_visitor<T>(v)
        , _vo(_vo)
        , _ctx(_ctx) {}

    /**
     * Visit a single member and extract it from the variant object
     * @tparam Member - the member to visit
     * @tparam Class - the class we are traversing
     * @tparam member - pointer to the member
     * @param name - the name of the member
     */
    template <typename Member, class Class, Member(Class::*member)>
    void
    operator()(const char* name) const {
        auto itr = _vo.find(name);
        if(itr != _vo.end())
            abi_from_variant::extract(itr->value(), this->obj.*member, _ctx);
    }

private:
    const variant_object& _vo;
    abi_traverse_context& _ctx;
};

template <typename M, require_abi_t<M>>
void
abi_to_variant::add(mutable_variant_object& mvo, const char* name, const M& v, abi_traverse_context& ctx) {
    auto h          = ctx.enter_scope();
    auto member_mvo = mutable_variant_object();
    fc::reflector<M>::visit(impl::abi_to_variant_visitor<M>(member_mvo, v, ctx));
    mvo(name, std::move(member_mvo));
}

template <typename M, require_abi_t<M>>
void
abi_from_variant::extract(const variant& v, M& o, abi_traverse_context& ctx) {
    auto        h  = ctx.enter_scope();
    const auto& vo = v.get_object();
    fc::reflector<M>::visit(abi_from_variant_visitor<M>(vo, o, ctx));
}

}  // namespace impl

template <typename T>
void
abi_serializer::to_variant(const T& o, variant& vo, const execution_context& exec_ctx) const {
    try {
        auto mvo = mutable_variant_object();
        impl::abi_traverse_context ctx(*this, exec_ctx);
        impl::abi_to_variant::add(mvo, "_", o, ctx);
        vo = std::move(mvo["_"]);
    }
    FC_RETHROW_EXCEPTIONS(error, "Failed to serialize: ${type}", ("type", boost::core::demangle(typeid(o).name())));
}

template <typename T>
void
abi_serializer::from_variant(const variant& v, T& o, const execution_context& exec_ctx) const {
    try {
        impl::abi_traverse_context ctx(*this, exec_ctx);
        impl::abi_from_variant::extract(v, o, ctx);
    }
    FC_RETHROW_EXCEPTIONS(error, "Failed to deserialize variant", ("variant", v))
}

}}}  // namespace evt::chain::contracts
