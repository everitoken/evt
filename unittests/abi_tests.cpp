#include <algorithm>
#include <cstdlib>
#include <iterator>
#include <vector>

#include <catch/catch.hpp>

#include <fc/exception/exception.hpp>
#include <fc/io/json.hpp>
#include <fc/log/logger.hpp>
#include <fc/variant.hpp>

#include <evt/chain/contracts/abi_serializer.hpp>
#include <evt/chain/contracts/evt_contract.hpp>
#include <evt/chain/contracts/types.hpp>

using namespace evt;
using namespace chain;
using namespace contracts;

// verify that round trip conversion, via bytes, reproduces the exact same data
fc::variant
verify_byte_round_trip_conversion(const abi_serializer& abis, const type_name& type, const fc::variant& var) {
    auto bytes = abis.variant_to_binary(type, var);

    auto var2 = abis.binary_to_variant(type, bytes);

    std::string r = fc::json::to_string(var2);

    auto bytes2 = abis.variant_to_binary(type, var2);

    CHECK(fc::to_hex(bytes) == fc::to_hex(bytes2));

    return var2;
}

auto
get_evt_abi() {
    static auto abis = abi_serializer(evt_contract_abi());
    return abis;
}

// verify that round trip conversion, via actual class, reproduces the exact same data
template <typename T>
fc::variant
verify_type_round_trip_conversion(const abi_serializer& abis, const type_name& type, const fc::variant& var) {
    auto bytes = abis.variant_to_binary(type, var);

    T obj;
    fc::from_variant(var, obj);

    fc::variant var2;
    fc::to_variant(obj, var2);

    std::string r = fc::json::to_string(var2);

    auto bytes2 = abis.variant_to_binary(type, var2);

    CHECK(bytes.size() == bytes2.size());
    CHECK(fc::to_hex(bytes) == fc::to_hex(bytes2));

    return var2;
}

struct optionaltest {
    fc::optional<int> a;
    fc::optional<int> b;
};
FC_REFLECT(optionaltest, (a)(b));

struct optionaltest2 {
    fc::optional<optionaltest> a;
    fc::optional<optionaltest> b;
};
FC_REFLECT(optionaltest2, (a)(b));

TEST_CASE("optional_test", "[abis]") {
    auto abi = abi_def();
    abi.structs.emplace_back(struct_def{
        "optionaltest", "", {{"a", "int32?"}, {"b", "int32?"}}});
    abi.structs.emplace_back(struct_def{
        "optionaltest2", "", {{"a", "optionaltest?"}, {"b", "optionaltest?"}}});

    auto abis = abi_serializer(abi);

    auto json   = R"( { "a": 0 } )";
    auto json2  = R"( {"a": { "a": 0 } } )";
    auto var1   = fc::json::from_string(json);
    auto var2   = fc::json::from_string(json2);
    auto bytes1 = abis.variant_to_binary("optionaltest", var1);
    auto bytes2 = abis.variant_to_binary("optionaltest2", var2);

    CHECK(var1["a"].is_integer());
    CHECK_THROWS_AS(var1["b"].is_null(), fc::key_not_found_exception);

    CHECK((var2["a"].is_object() && var2["a"].get_object().size() > 0));
    CHECK_THROWS_AS((var2["b"].is_object() && var2["b"].get_object().size() == 0), fc::key_not_found_exception);

    optionaltest ot;
    fc::from_variant(var1, ot);

    optionaltest2 ot2;
    fc::from_variant(var2, ot2);

    CHECK(ot.a.valid());
    CHECK(!ot.b.valid());

    CHECK(ot2.a.valid());
    CHECK(!ot2.b.valid());

    fc::variant var21, var22;
    fc::to_variant(ot, var21);
    fc::to_variant(ot2, var22);

    CHECK(var21["a"].is_integer());
    CHECK_THROWS_AS(var21["b"].is_null(), fc::key_not_found_exception);

    CHECK((var22["a"].is_object() && var22["a"].get_object().size() > 0));
    CHECK_THROWS_AS((var22["b"].is_object() && var22["b"].get_object().size() == 0), fc::key_not_found_exception);

    auto bytes21 = abis.variant_to_binary("optionaltest", var21);
    CHECK(fc::to_hex(bytes1) == fc::to_hex(bytes21));

    auto bytes22 = abis.variant_to_binary("optionaltest2", var22);
    CHECK(fc::to_hex(bytes2) == fc::to_hex(bytes22));
}

TEST_CASE("newdomain_test", "[abis]") {
    auto abis = get_evt_abi();

    CHECK(true);
    const char* test_data = R"=====(
    {
      "name" : "cookie",
      "creator" : "EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK",
      "issue" : {
        "name" : "issue",
        "threshold" : 1,
        "authorizers": [{
            "ref": "[A] EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK",
            "weight": 1
          }
        ]
      },
      "transfer": {
        "name": "transfer",
        "threshold": 1,
        "authorizers": [{
            "ref": "[G] .OWNER",
            "weight": 1
          }
        ]
      },
      "manage": {
        "name": "manage",
        "threshold": 1,
        "authorizers": [{
            "ref": "[A] EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK",
            "weight": 1
          }
        ]
      }
    }
    )=====";

    auto var    = fc::json::from_string(test_data);
    auto newdom = var.as<newdomain>();
    CHECK("cookie" == newdom.name);
    CHECK("EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK" == (std::string)newdom.creator);

    CHECK("issue" == newdom.issue.name);
    CHECK(1 == newdom.issue.threshold);
    REQUIRE(1 == newdom.issue.authorizers.size());
    CHECK(newdom.issue.authorizers[0].ref.is_account_ref());
    CHECK("EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK" == (std::string)newdom.issue.authorizers[0].ref.get_account());
    CHECK(1 == newdom.issue.authorizers[0].weight);

    CHECK("transfer" == newdom.transfer.name);
    CHECK(1 == newdom.transfer.threshold);
    REQUIRE(1 == newdom.transfer.authorizers.size());
    CHECK(newdom.transfer.authorizers[0].ref.is_owner_ref());
    CHECK(1 == newdom.transfer.authorizers[0].weight);

    CHECK("manage" == newdom.manage.name);
    CHECK(1 == newdom.manage.threshold);
    REQUIRE(1 == newdom.manage.authorizers.size());
    CHECK(newdom.manage.authorizers[0].ref.is_account_ref());
    CHECK("EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK" == (std::string)newdom.manage.authorizers[0].ref.get_account());
    CHECK(1 == newdom.manage.authorizers[0].weight);

    auto var2    = verify_byte_round_trip_conversion(abis, "newdomain", var);
    auto newdom2 = var2.as<newdomain>();
    CHECK(newdom2.name == newdom.name);
    CHECK((std::string)newdom2.creator == (std::string)newdom.creator);

    CHECK(newdom2.issue.name == newdom.issue.name);
    CHECK(newdom2.issue.threshold == newdom.issue.threshold);
    REQUIRE(newdom2.issue.authorizers.size() == newdom.issue.authorizers.size());
    CHECK(newdom2.issue.authorizers[0].ref.type() == newdom.issue.authorizers[0].ref.type());
    CHECK((std::string)newdom2.issue.authorizers[0].ref.get_account() == (std::string)newdom.issue.authorizers[0].ref.get_account());
    CHECK(newdom2.issue.authorizers[0].weight == newdom.issue.authorizers[0].weight);

    CHECK(newdom2.transfer.name == newdom.transfer.name);
    CHECK(newdom2.transfer.threshold == newdom.transfer.threshold);
    REQUIRE(newdom2.transfer.authorizers.size() == newdom.transfer.authorizers.size());
    CHECK(newdom2.transfer.authorizers[0].ref.type() == newdom.transfer.authorizers[0].ref.type());
    CHECK(newdom2.transfer.authorizers[0].weight == newdom.transfer.authorizers[0].weight);

    CHECK(newdom2.manage.name == newdom.manage.name);
    CHECK(newdom2.manage.threshold == newdom.manage.threshold);
    REQUIRE(newdom2.manage.authorizers.size() == newdom.manage.authorizers.size());
    CHECK(newdom2.transfer.authorizers[0].ref.type() == newdom.transfer.authorizers[0].ref.type());
    CHECK((std::string)newdom2.manage.authorizers[0].ref.get_account() == (std::string)newdom.manage.authorizers[0].ref.get_account());
    CHECK(newdom2.manage.authorizers[0].weight == newdom.manage.authorizers[0].weight);

    verify_type_round_trip_conversion<newdomain>(abis, "newdomain", var);
}

TEST_CASE("updatedomain_test", "[abis]") {
    auto abis = get_evt_abi();

    CHECK(true);
    const char* test_data = R"=====(
    {
      "name" : "cookie",
      "issue" : {
        "name": "issue",
        "threshold": 2,
        "authorizers": [{
          "ref": "[A] EVT8MGU4aKiVzqMtWi9zLpu8KuTHZWjQQrX475ycSxEkLd6aBpraX",
          "weight": 1},{
            "ref": "[G] new-group",
            "weight": 1
          } ]
      }
    }
    )=====";

    auto var   = fc::json::from_string(test_data);
    auto updom = var.as<updatedomain>();

    CHECK("cookie" == updom.name);

    CHECK("issue" == updom.issue->name);
    CHECK(2 == updom.issue->threshold);
    REQUIRE(2 == updom.issue->authorizers.size());
    REQUIRE(updom.issue->authorizers[0].ref.is_account_ref());
    CHECK("EVT8MGU4aKiVzqMtWi9zLpu8KuTHZWjQQrX475ycSxEkLd6aBpraX" == (std::string)updom.issue->authorizers[0].ref.get_account());
    CHECK(1 == updom.issue->authorizers[0].weight);

    auto var2   = verify_byte_round_trip_conversion(abis, "updatedomain", var);
    auto updom2 = var2.as<updatedomain>();

    CHECK("cookie" == updom2.name);

    CHECK("issue" == updom2.issue->name);
    CHECK(2 == updom2.issue->threshold);
    REQUIRE(2 == updom2.issue->authorizers.size());
    REQUIRE(updom2.issue->authorizers[0].ref.is_account_ref());
    CHECK("EVT8MGU4aKiVzqMtWi9zLpu8KuTHZWjQQrX475ycSxEkLd6aBpraX" == (std::string)updom2.issue->authorizers[0].ref.get_account());
    CHECK(1 == updom2.issue->authorizers[0].weight);

    verify_type_round_trip_conversion<updatedomain>(abis, "updatedomain", var);
}

TEST_CASE("issuetoken_test", "[abis]") {
    auto abis = get_evt_abi();

    CHECK(true);
    const char* test_data = R"=====(
    {
      "domain": "cookie",
        "names": [
          "t1",
          "t2",
          "t3"
        ],
        "owner": [
          "EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK"
        ]
    }
    )=====";

    auto var  = fc::json::from_string(test_data);
    auto istk = var.as<issuetoken>();

    CHECK("cookie" == istk.domain);

    REQUIRE(3 == istk.names.size());
    CHECK("t1" == istk.names[0]);
    CHECK("t2" == istk.names[1]);
    CHECK("t3" == istk.names[2]);

    REQUIRE(1 == istk.owner.size());
    CHECK("EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK" == (std::string)istk.owner[0]);

    auto var2  = verify_byte_round_trip_conversion(abis, "issuetoken", var);
    auto istk2 = var2.as<issuetoken>();

    CHECK("cookie" == istk2.domain);

    REQUIRE(3 == istk2.names.size());
    CHECK("t1" == istk2.names[0]);
    CHECK("t2" == istk2.names[1]);
    CHECK("t3" == istk2.names[2]);

    REQUIRE(1 == istk2.owner.size());
    CHECK("EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK" == (std::string)istk2.owner[0]);

    verify_type_round_trip_conversion<issuetoken>(abis, "issuetoken", var);
}

TEST_CASE("transfer_test", "[abis]") {
    auto abis = get_evt_abi();

    CHECK(true);
    const char* test_data = R"=====(
    {
      "domain": "cookie",
      "name": "t1",
      "to": [
        "EVT8MGU4aKiVzqMtWi9zLpu8KuTHZWjQQrX475ycSxEkLd6aBpraX"
      ],
      "memo":"memo"
    }
    )=====";

    auto var = fc::json::from_string(test_data);
    auto trf = var.as<transfer>();

    CHECK("cookie" == trf.domain);
    CHECK("t1" == trf.name);

    REQUIRE(1 == trf.to.size());
    CHECK("EVT8MGU4aKiVzqMtWi9zLpu8KuTHZWjQQrX475ycSxEkLd6aBpraX" == (std::string)trf.to[0]);
    CHECK("memo" == trf.memo);

    auto var2 = verify_byte_round_trip_conversion(abis, "transfer", var);
    auto trf2 = var2.as<transfer>();

    CHECK("cookie" == trf2.domain);
    CHECK("t1" == trf2.name);

    REQUIRE(1 == trf2.to.size());
    CHECK("EVT8MGU4aKiVzqMtWi9zLpu8KuTHZWjQQrX475ycSxEkLd6aBpraX" == (std::string)trf2.to[0]);
    CHECK("memo" == trf2.memo);

    verify_type_round_trip_conversion<transfer>(abis, "transfer", var);
}

TEST_CASE("destroytoken_test", "[abis]") {
    auto abis = get_evt_abi();

    CHECK(true);
    const char* test_data = R"=====(
    {
      "domain": "cookie",
      "name": "t1"
    }
    )=====";

    auto var   = fc::json::from_string(test_data);
    auto destk = var.as<destroytoken>();

    CHECK("cookie" == destk.domain);
    CHECK("t1" == destk.name);

    auto var2   = verify_byte_round_trip_conversion(abis, "destroytoken", var);
    auto destk2 = var2.as<destroytoken>();

    CHECK("cookie" == destk2.domain);
    CHECK("t1" == destk2.name);

    verify_type_round_trip_conversion<transfer>(abis, "destroytoken", var);
}

TEST_CASE("newgroup_test", "[abis]") {
    auto abis = get_evt_abi();

    CHECK(true);
    const char* test_data = R"=====(
    {
      "name" : "5jxX",
      "group" : {
        "name": "5jxXg",
        "key": "EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV",
        "root": {
          "threshold": 6,
          "weight": 0,
          "nodes": [{
              "type": "branch",
              "threshold": 1,
              "weight": 3,
              "nodes": [{
                  "key": "EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV",
                  "weight": 1
                },{
                  "key": "EVT8MGU4aKiVzqMtWi9zLpu8KuTHZWjQQrX475ycSxEkLd6aBpraX",
                  "weight": 1
                }
              ]
            },{
              "key": "EVT8MGU4aKiVzqMtWi9zLpu8KuTHZWjQQrX475ycSxEkLd6aBpraX",
              "weight": 3
            },{
              "threshold": 1,
              "weight": 3,
              "nodes": [{
                  "key": "EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV",
                  "weight": 1
                },{
                  "key": "EVT8MGU4aKiVzqMtWi9zLpu8KuTHZWjQQrX475ycSxEkLd6aBpraX",
                  "weight": 2
                }
              ]
            }
          ]
        }
      }
    }
    )=====";

    auto var = fc::json::from_string(test_data);

    auto newgrp = var.as<newgroup>();
    CHECK("5jxX" == newgrp.name);

    CHECK("5jxXg" == newgrp.group.name());
    CHECK("EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV" == (std::string)newgrp.group.key());

    auto root = newgrp.group.root();
    REQUIRE(root.validate());
    REQUIRE(root.is_root());
    REQUIRE(3 == root.size);
    CHECK(1 == root.index);
    CHECK(6 == root.threshold);
    CHECK(0 == root.weight);

    auto son0 = newgrp.group.get_child_node(root, 0);
    REQUIRE(son0.validate());
    REQUIRE(2 == son0.size);
    CHECK(1 == son0.threshold);
    CHECK(3 == son0.weight);

    auto son0_son0 = newgrp.group.get_child_node(son0, 0);
    REQUIRE(son0_son0.validate());
    REQUIRE(son0_son0.is_leaf());
    CHECK("EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV" == (std::string)newgrp.group.get_leaf_key(son0_son0));
    CHECK(1 == son0_son0.weight);

    auto son0_son1 = newgrp.group.get_child_node(son0, 1);
    REQUIRE(son0_son1.validate());
    REQUIRE(son0_son1.is_leaf());
    CHECK("EVT8MGU4aKiVzqMtWi9zLpu8KuTHZWjQQrX475ycSxEkLd6aBpraX" == (std::string)newgrp.group.get_leaf_key(son0_son1));
    CHECK(1 == son0_son1.weight);

    auto son1 = newgrp.group.get_child_node(root, 1);
    REQUIRE(son1.validate());
    REQUIRE(son1.is_leaf());
    CHECK("EVT8MGU4aKiVzqMtWi9zLpu8KuTHZWjQQrX475ycSxEkLd6aBpraX" == (std::string)newgrp.group.get_leaf_key(son1));
    CHECK(3 == son1.weight);

    auto son2 = newgrp.group.get_child_node(root, 2);
    REQUIRE(son2.validate());
    REQUIRE(2 == son2.size);
    CHECK(1 == son2.threshold);
    CHECK(3 == son2.weight);

    auto son2_son0 = newgrp.group.get_child_node(son2, 0);
    REQUIRE(son2_son0.validate());
    REQUIRE(son2_son0.is_leaf());
    CHECK("EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV" == (std::string)newgrp.group.get_leaf_key(son2_son0));
    CHECK(1 == son2_son0.weight);

    auto son2_son1 = newgrp.group.get_child_node(son2, 1);
    REQUIRE(son2_son1.validate());
    REQUIRE(son2_son1.is_leaf());
    CHECK("EVT8MGU4aKiVzqMtWi9zLpu8KuTHZWjQQrX475ycSxEkLd6aBpraX" == (std::string)newgrp.group.get_leaf_key(son2_son1));
    CHECK(2 == son2_son1.weight);

    auto var2    = verify_byte_round_trip_conversion(abis, "newgroup", var);
    auto newgrp2 = var2.as<newgroup>();

    CHECK("5jxX" == newgrp2.name);

    CHECK("5jxXg" == newgrp2.group.name());
    CHECK("EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV" == (std::string)newgrp2.group.key());

    root = newgrp2.group.root();
    REQUIRE(root.validate());
    REQUIRE(root.is_root());
    REQUIRE(3 == root.size);
    CHECK(1 == root.index);
    CHECK(6 == root.threshold);
    CHECK(0 == root.weight);

    son0 = newgrp2.group.get_child_node(root, 0);
    REQUIRE(son0.validate());
    REQUIRE(2 == son0.size);
    CHECK(1 == son0.threshold);
    CHECK(3 == son0.weight);

    son0_son0 = newgrp2.group.get_child_node(son0, 0);
    REQUIRE(son0_son0.validate());
    REQUIRE(son0_son0.is_leaf());
    CHECK("EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV" == (std::string)newgrp2.group.get_leaf_key(son0_son0));
    CHECK(1 == son0_son0.weight);

    son0_son1 = newgrp2.group.get_child_node(son0, 1);
    REQUIRE(son0_son1.validate());
    REQUIRE(son0_son1.is_leaf());
    CHECK("EVT8MGU4aKiVzqMtWi9zLpu8KuTHZWjQQrX475ycSxEkLd6aBpraX" == (std::string)newgrp2.group.get_leaf_key(son0_son1));
    CHECK(1 == son0_son1.weight);

    son1 = newgrp2.group.get_child_node(root, 1);
    REQUIRE(son1.validate());
    REQUIRE(son1.is_leaf());
    CHECK("EVT8MGU4aKiVzqMtWi9zLpu8KuTHZWjQQrX475ycSxEkLd6aBpraX" == (std::string)newgrp2.group.get_leaf_key(son1));
    CHECK(3 == son1.weight);

    son2 = newgrp2.group.get_child_node(root, 2);
    REQUIRE(son2.validate());
    REQUIRE(2 == son2.size);
    CHECK(1 == son2.threshold);
    CHECK(3 == son2.weight);

    son2_son0 = newgrp2.group.get_child_node(son2, 0);
    REQUIRE(son2_son0.validate());
    REQUIRE(son2_son0.is_leaf());
    CHECK("EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV" == (std::string)newgrp2.group.get_leaf_key(son2_son0));
    CHECK(1 == son2_son0.weight);

    son2_son1 = newgrp2.group.get_child_node(son2, 1);
    REQUIRE(son2_son1.validate());
    REQUIRE(son2_son1.is_leaf());
    CHECK("EVT8MGU4aKiVzqMtWi9zLpu8KuTHZWjQQrX475ycSxEkLd6aBpraX" == (std::string)newgrp2.group.get_leaf_key(son2_son1));
    CHECK(2 == son2_son1.weight);

    verify_type_round_trip_conversion<newgroup>(abis, "newgroup", var);
}

TEST_CASE("updategroup_test", "[abis]") {
    auto abis = get_evt_abi();

    CHECK(true);
    const char* test_data = R"=====(
    {
      "name" : "5jxX",
      "group" : {
        "name": "5jxXg",
        "key": "EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV",
        "root": {
          "threshold": 6,
          "weight": 0,
          "nodes": [{
              "type": "branch",
              "threshold": 1,
              "weight": 3,
              "nodes": [{
                  "key": "EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV",
                  "weight": 1
                },{
                  "key": "EVT8MGU4aKiVzqMtWi9zLpu8KuTHZWjQQrX475ycSxEkLd6aBpraX",
                  "weight": 1
                }
              ]
            },{
              "key": "EVT8MGU4aKiVzqMtWi9zLpu8KuTHZWjQQrX475ycSxEkLd6aBpraX",
              "weight": 3
            },{
              "threshold": 1,
              "weight": 3,
              "nodes": [{
                  "key": "EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV",
                  "weight": 1
                },{
                  "key": "EVT8MGU4aKiVzqMtWi9zLpu8KuTHZWjQQrX475ycSxEkLd6aBpraX",
                  "weight": 2
                }
              ]
            }
          ]
        }
      }
    }
    )=====";

    auto var = fc::json::from_string(test_data);

    auto upgrp = var.as<updategroup>();
    CHECK("5jxX" == upgrp.name);

    CHECK("5jxXg" == upgrp.group.name());
    CHECK("EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV" == (std::string)upgrp.group.key());

    auto root = upgrp.group.root();
    REQUIRE(root.validate());
    REQUIRE(root.is_root());
    REQUIRE(3 == root.size);
    CHECK(1 == root.index);
    CHECK(6 == root.threshold);
    CHECK(0 == root.weight);

    auto son0 = upgrp.group.get_child_node(root, 0);
    REQUIRE(son0.validate());
    REQUIRE(2 == son0.size);
    CHECK(1 == son0.threshold);
    CHECK(3 == son0.weight);

    auto son0_son0 = upgrp.group.get_child_node(son0, 0);
    REQUIRE(son0_son0.validate());
    REQUIRE(son0_son0.is_leaf());
    CHECK("EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV" == (std::string)upgrp.group.get_leaf_key(son0_son0));
    CHECK(1 == son0_son0.weight);

    auto son0_son1 = upgrp.group.get_child_node(son0, 1);
    REQUIRE(son0_son1.validate());
    REQUIRE(son0_son1.is_leaf());
    CHECK("EVT8MGU4aKiVzqMtWi9zLpu8KuTHZWjQQrX475ycSxEkLd6aBpraX" == (std::string)upgrp.group.get_leaf_key(son0_son1));
    CHECK(1 == son0_son1.weight);

    auto son1 = upgrp.group.get_child_node(root, 1);
    REQUIRE(son1.validate());
    REQUIRE(son1.is_leaf());
    CHECK("EVT8MGU4aKiVzqMtWi9zLpu8KuTHZWjQQrX475ycSxEkLd6aBpraX" == (std::string)upgrp.group.get_leaf_key(son1));
    CHECK(3 == son1.weight);

    auto son2 = upgrp.group.get_child_node(root, 2);
    REQUIRE(son2.validate());
    REQUIRE(2 == son2.size);
    CHECK(1 == son2.threshold);
    CHECK(3 == son2.weight);

    auto son2_son0 = upgrp.group.get_child_node(son2, 0);
    REQUIRE(son2_son0.validate());
    REQUIRE(son2_son0.is_leaf());
    CHECK("EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV" == (std::string)upgrp.group.get_leaf_key(son2_son0));
    CHECK(1 == son2_son0.weight);

    auto son2_son1 = upgrp.group.get_child_node(son2, 1);
    REQUIRE(son2_son1.validate());
    REQUIRE(son2_son1.is_leaf());
    CHECK("EVT8MGU4aKiVzqMtWi9zLpu8KuTHZWjQQrX475ycSxEkLd6aBpraX" == (std::string)upgrp.group.get_leaf_key(son2_son1));
    CHECK(2 == son2_son1.weight);

    auto var2   = verify_byte_round_trip_conversion(abis, "updategroup", var);
    auto upgrp2 = var2.as<updategroup>();

    CHECK("5jxX" == upgrp2.name);

    CHECK("5jxXg" == upgrp2.group.name());
    CHECK("EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV" == (std::string)upgrp2.group.key());

    root = upgrp2.group.root();
    REQUIRE(root.validate());
    REQUIRE(root.is_root());
    REQUIRE(3 == root.size);
    CHECK(1 == root.index);
    CHECK(6 == root.threshold);
    CHECK(0 == root.weight);

    son0 = upgrp2.group.get_child_node(root, 0);
    REQUIRE(son0.validate());
    REQUIRE(2 == son0.size);
    CHECK(1 == son0.threshold);
    CHECK(3 == son0.weight);

    son0_son0 = upgrp2.group.get_child_node(son0, 0);
    REQUIRE(son0_son0.validate());
    REQUIRE(son0_son0.is_leaf());
    CHECK("EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV" == (std::string)upgrp2.group.get_leaf_key(son0_son0));
    CHECK(1 == son0_son0.weight);

    son0_son1 = upgrp2.group.get_child_node(son0, 1);
    REQUIRE(son0_son1.validate());
    REQUIRE(son0_son1.is_leaf());
    CHECK("EVT8MGU4aKiVzqMtWi9zLpu8KuTHZWjQQrX475ycSxEkLd6aBpraX" == (std::string)upgrp2.group.get_leaf_key(son0_son1));
    CHECK(1 == son0_son1.weight);

    son1 = upgrp2.group.get_child_node(root, 1);
    REQUIRE(son1.validate());
    REQUIRE(son1.is_leaf());
    CHECK("EVT8MGU4aKiVzqMtWi9zLpu8KuTHZWjQQrX475ycSxEkLd6aBpraX" == (std::string)upgrp2.group.get_leaf_key(son1));
    CHECK(3 == son1.weight);

    son2 = upgrp2.group.get_child_node(root, 2);
    REQUIRE(son2.validate());
    REQUIRE(2 == son2.size);
    CHECK(1 == son2.threshold);
    CHECK(3 == son2.weight);

    son2_son0 = upgrp2.group.get_child_node(son2, 0);
    REQUIRE(son2_son0.validate());
    REQUIRE(son2_son0.is_leaf());
    CHECK("EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV" == (std::string)upgrp2.group.get_leaf_key(son2_son0));
    CHECK(1 == son2_son0.weight);

    son2_son1 = upgrp2.group.get_child_node(son2, 1);
    REQUIRE(son2_son1.validate());
    REQUIRE(son2_son1.is_leaf());
    CHECK("EVT8MGU4aKiVzqMtWi9zLpu8KuTHZWjQQrX475ycSxEkLd6aBpraX" == (std::string)upgrp2.group.get_leaf_key(son2_son1));
    CHECK(2 == son2_son1.weight);

    verify_type_round_trip_conversion<updategroup>(abis, "updategroup", var);
}

TEST_CASE("newfungible_test", "[abis]") {
    auto abis = get_evt_abi();

    const char* test_data = R"=====(
    {
      "sym": "5,EVT",
      "creator": "EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV",
      "issue" : {
        "name" : "issue",
        "threshold" : 1,
        "authorizers": [{
            "ref": "[A] EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK",
            "weight": 1
          }
        ]
      },
      "manage": {
        "name": "manage",
        "threshold": 1,
        "authorizers": [{
            "ref": "[A] EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK",
            "weight": 1
          }
        ]
      },
      "total_supply":"12.00000 EVT"
    }
    )=====";

    auto var   = fc::json::from_string(test_data);
    auto newfg = var.as<newfungible>();

    CHECK("5,EVT" == newfg.sym.to_string());
    CHECK("EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV" == (std::string)newfg.creator);

    CHECK("issue" == newfg.issue.name);
    CHECK(1 == newfg.issue.threshold);
    REQUIRE(1 == newfg.issue.authorizers.size());
    CHECK(newfg.issue.authorizers[0].ref.is_account_ref());
    CHECK("EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK" == (std::string)newfg.issue.authorizers[0].ref.get_account());
    CHECK(1 == newfg.issue.authorizers[0].weight);

    CHECK("manage" == newfg.manage.name);
    CHECK(1 == newfg.manage.threshold);
    REQUIRE(1 == newfg.manage.authorizers.size());
    CHECK(newfg.manage.authorizers[0].ref.is_account_ref());
    CHECK("EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK" == (std::string)newfg.manage.authorizers[0].ref.get_account());
    CHECK(1 == newfg.manage.authorizers[0].weight);

    CHECK(1200000 == newfg.total_supply.get_amount());
    CHECK("5,EVT" == newfg.total_supply.get_symbol().to_string());
    CHECK("12.00000 EVT" == newfg.total_supply.to_string());

    auto var2 = verify_byte_round_trip_conversion(abis, "newfungible", var);

    auto newfg2 = var2.as<newfungible>();

    CHECK("5,EVT" == newfg2.sym.to_string());
    CHECK("EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV" == (std::string)newfg2.creator);

    CHECK("issue" == newfg2.issue.name);
    CHECK(1 == newfg2.issue.threshold);
    REQUIRE(1 == newfg2.issue.authorizers.size());
    CHECK(newfg2.issue.authorizers[0].ref.is_account_ref());
    CHECK("EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK" == (std::string)newfg2.issue.authorizers[0].ref.get_account());
    CHECK(1 == newfg2.issue.authorizers[0].weight);

    CHECK("manage" == newfg2.manage.name);
    CHECK(1 == newfg2.manage.threshold);
    REQUIRE(1 == newfg2.manage.authorizers.size());
    CHECK(newfg2.manage.authorizers[0].ref.is_account_ref());
    CHECK("EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK" == (std::string)newfg2.manage.authorizers[0].ref.get_account());
    CHECK(1 == newfg2.manage.authorizers[0].weight);

    CHECK(1200000 == newfg2.total_supply.get_amount());
    CHECK("5,EVT" == newfg2.total_supply.get_symbol().to_string());
    CHECK("12.00000 EVT" == newfg2.total_supply.to_string());

    verify_type_round_trip_conversion<newfungible>(abis, "newfungible", var);
}

TEST_CASE("updfungible_test", "[abis]") {
    auto abis = get_evt_abi();

    const char* test_data = R"=====(
    {
      "sym": "5,EVT",
      "issue" : {
        "name" : "issue2",
        "threshold" : 1,
        "authorizers": [{
            "ref": "[A] EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK",
            "weight": 1
          }
        ]
      }
    }
    )=====";

    auto var   = fc::json::from_string(test_data);
    auto updfg = var.as<updfungible>();

    CHECK("5,EVT" == updfg.sym.to_string());

    CHECK("issue2" == updfg.issue->name);
    CHECK(1 == updfg.issue->threshold);
    REQUIRE(1 == updfg.issue->authorizers.size());
    CHECK(updfg.issue->authorizers[0].ref.is_account_ref());
    CHECK("EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK" == (std::string)updfg.issue->authorizers[0].ref.get_account());
    CHECK(1 == updfg.issue->authorizers[0].weight);

    auto var2 = verify_byte_round_trip_conversion(abis, "updfungible", var);

    auto updfg2 = var2.as<updfungible>();

    CHECK("5,EVT" == updfg2.sym.to_string());

    CHECK("issue2" == updfg2.issue->name);
    CHECK(1 == updfg2.issue->threshold);
    REQUIRE(1 == updfg2.issue->authorizers.size());
    CHECK(updfg2.issue->authorizers[0].ref.is_account_ref());
    CHECK("EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK" == (std::string)updfg2.issue->authorizers[0].ref.get_account());
    CHECK(1 == updfg2.issue->authorizers[0].weight);

    verify_type_round_trip_conversion<updfungible>(abis, "updfungible", var);
}

TEST_CASE("issuefungible_test", "[abis]") {
    auto abis = get_evt_abi();

    const char* test_data = R"=====(
    {
      "address": "EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK",
      "number" : "12.00000 EVT",
      "memo": "memo"
    }
    )=====";

    auto var   = fc::json::from_string(test_data);
    auto issfg = var.as<issuefungible>();

    CHECK("EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK" == (std::string)issfg.address);
    CHECK("memo" == issfg.memo);

    CHECK(1200000 == issfg.number.get_amount());
    CHECK("5,EVT" == issfg.number.get_symbol().to_string());
    CHECK("12.00000 EVT" == issfg.number.to_string());

    auto var2 = verify_byte_round_trip_conversion(abis, "issuefungible", var);

    auto issfg2 = var2.as<issuefungible>();

    CHECK("EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK" == (std::string)issfg2.address);
    CHECK("memo" == issfg2.memo);

    CHECK(1200000 == issfg2.number.get_amount());
    CHECK("5,EVT" == issfg2.number.get_symbol().to_string());
    CHECK("12.00000 EVT" == issfg2.number.to_string());

    verify_type_round_trip_conversion<issuefungible>(abis, "issuefungible", var);
}

TEST_CASE("transferft_test", "[abis]") {
    auto abis = get_evt_abi();

    const char* test_data = R"=====(
    {
      "from": "EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK",
      "to": "EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK",
      "number" : "12.00000 EVT",
      "memo": "memo"
    }
    )=====";

    auto var  = fc::json::from_string(test_data);
    auto trft = var.as<transferft>();

    CHECK("EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK" == (std::string)trft.from);
    CHECK("EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK" == (std::string)trft.to);
    CHECK("memo" == trft.memo);

    CHECK(1200000 == trft.number.get_amount());
    CHECK("5,EVT" == trft.number.get_symbol().to_string());
    CHECK("12.00000 EVT" == trft.number.to_string());

    auto var2 = verify_byte_round_trip_conversion(abis, "transferft", var);

    auto trft2 = var2.as<transferft>();

    CHECK("EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK" == (std::string)trft2.from);
    CHECK("EVT546WaW3zFAxEEEkYKjDiMvg3CHRjmWX2XdNxEhi69RpdKuQRSK" == (std::string)trft2.to);
    CHECK("memo" == trft2.memo);

    CHECK(1200000 == trft2.number.get_amount());
    CHECK("5,EVT" == trft2.number.get_symbol().to_string());
    CHECK("12.00000 EVT" == trft2.number.to_string());

    verify_type_round_trip_conversion<transferft>(abis, "transferft", var);
}

TEST_CASE("addmeta_test", "[abis]") {
    auto abis = get_evt_abi();

    CHECK(true);
    const char* test_data = R"=====(
    {
      "key": "key",
      "value": "value",
      "creator": "[A] EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"
    }
    )=====";

    auto var  = fc::json::from_string(test_data);
    auto admt = var.as<addmeta>();

    CHECK("key" == admt.key);
    CHECK("value" == admt.value);
    CHECK(admt.creator.is_account_ref());
    CHECK("EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV" == (std::string)admt.creator.get_account());

    auto var2 = verify_byte_round_trip_conversion(abis, "addmeta", var);

    auto admt2 = var2.as<addmeta>();

    CHECK("key" == admt2.key);
    CHECK("value" == admt2.value);
    CHECK(admt2.creator.is_account_ref());
    CHECK("EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV" == (std::string)admt2.creator.get_account());

    verify_type_round_trip_conversion<addmeta>(abis, "addmeta", var);
}

TEST_CASE("newsuspend_test", "[abis]") {
    auto abis = get_evt_abi();
    CHECK(true);
    const char* test_data = R"=======(
    {
        "name": "testsuspend",
        "proposer": "EVT6bMPrzVm77XSjrTfZxEsbAuWPuJ9hCqGRLEhkTjANWuvWTbwe3",
        "trx": {
            "expiration": "2018-07-04T05:14:12",
            "ref_block_num": "3432",
            "ref_block_prefix": "291678901",
            "max_charge": 10000,
            "payer": "EVT6bMPrzVm77XSjrTfZxEsbAuWPuJ9hCqGRLEhkTjANWuvWTbwe3",
            "actions": [
                {
                    "name": "newdomain",
                    "domain": "test1530681222",
                    "key": ".create",
                    "data": "00000000004010c4a02042710c9f077d0002e07ae3ed523dba04dc9d718d94abcd1bea3da38176f4b775b818200c01a149b1000000008052e74c01000000010100000002e07ae3ed523dba04dc9d718d94abcd1bea3da38176f4b775b818200c01a149b1000000000000000100000000b298e982a40100000001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000094135c6801000000010100000002e07ae3ed523dba04dc9d718d94abcd1bea3da38176f4b775b818200c01a149b1000000000000000100"
                }
            ],
            "transaction_extensions": []
        }
    }
    )=======";

    auto var   = fc::json::from_string(test_data);
    auto ndact = var.as<newsuspend>();

    CHECK("testsuspend" == (std::string)ndact.name);
    CHECK("EVT6bMPrzVm77XSjrTfZxEsbAuWPuJ9hCqGRLEhkTjANWuvWTbwe3" == (std::string)ndact.proposer);
    CHECK("2018-07-04T05:14:12" == ndact.trx.expiration.to_iso_string());
    CHECK(3432 == ndact.trx.ref_block_num);
    CHECK(291678901 == ndact.trx.ref_block_prefix);
    CHECK(ndact.trx.actions.size() == 1);
    CHECK("newdomain" == ndact.trx.actions[0].name);
    CHECK("test1530681222" == ndact.trx.actions[0].domain);
    CHECK(".create" == ndact.trx.actions[0].key);

    verify_byte_round_trip_conversion(abis, "newsuspend", var);
    verify_type_round_trip_conversion<newsuspend>(abis, "newsuspend", var);
}

TEST_CASE("cancelsuspend_test", "[abis]") {
    auto abis = get_evt_abi();
    CHECK(true);
    const char* test_data = R"=======(
    {
        "name": "testsuspend",
    }
    )=======";

    auto var   = fc::json::from_string(test_data);
    auto cdact = var.as<cancelsuspend>();

    CHECK("testsuspend" == (std::string)cdact.name);

    verify_byte_round_trip_conversion(abis, "cancelsuspend", var);
    verify_type_round_trip_conversion<cancelsuspend>(abis, "cancelsuspend", var);
}

TEST_CASE("aprvsuspend_test", "[abis]") {
    auto abis = get_evt_abi();
    CHECK(true);
    const char* test_data = R"=======(
    {
        "name": "test1530718665",
        "signatures": [
            "SIG_K1_KXjtmeihJi1qnSs7vmqJDRJoZ1nSEPeeRjsKJRpm24g8yhFtAepkRDR4nVFbXjvoaQvT4QrzuNWCbuEhceYpGmAvsG47Fj"
        ]
    }
    )=======";

    auto var   = fc::json::from_string(test_data);
    auto adact = var.as<aprvsuspend>();

    CHECK("test1530718665" == (std::string)adact.name);
    CHECK(adact.signatures.size() == 1);
    CHECK((std::string)adact.signatures[0] == "SIG_K1_KXjtmeihJi1qnSs7vmqJDRJoZ1nSEPeeRjsKJRpm24g8yhFtAepkRDR4nVFbXjvoaQvT4QrzuNWCbuEhceYpGmAvsG47Fj");

    verify_byte_round_trip_conversion(abis, "aprvsuspend", var);
    verify_type_round_trip_conversion<aprvsuspend>(abis, "aprvsuspend", var);
}

TEST_CASE("execsuspend_test", "[abis]") {
    auto abis = get_evt_abi();
    CHECK(true);
    const char* test_data = R"=======(
    {
        "name": "test1530718626",
        "executor": "EVT548LviBDF6EcknKnKUMeaPUrZN2uhfCB1XrwHsURZngakYq9Vx"

    }
    )=======";

    auto var   = fc::json::from_string(test_data);
    auto edact = var.as<execsuspend>();

    CHECK("test1530718626" == (std::string)edact.name);
    CHECK((std::string)edact.executor == "EVT548LviBDF6EcknKnKUMeaPUrZN2uhfCB1XrwHsURZngakYq9Vx");

    verify_byte_round_trip_conversion(abis, "execsuspend", var);
    verify_type_round_trip_conversion<execsuspend>(abis, "execsuspend", var);
}

TEST_CASE("evt2pevt_test", "[abis]") {
    auto abis = get_evt_abi();
    CHECK(true);
    const char* test_data = R"=======(
    {
        "from": "EVT6bMPrzVm77XSjrTfZxEsbAuWPuJ9hCqGRLEhkTjANWuvWTbwe3",
        "to": "EVT548LviBDF6EcknKnKUMeaPUrZN2uhfCB1XrwHsURZngakYq9Vx",
        "number": "5.00000 EVT",
        "memo": "memo"
    }
    )=======";

    auto var = fc::json::from_string(test_data);
    auto e2p = var.as<evt2pevt>();

    CHECK("EVT6bMPrzVm77XSjrTfZxEsbAuWPuJ9hCqGRLEhkTjANWuvWTbwe3" == (std::string)e2p.from);
    CHECK("EVT548LviBDF6EcknKnKUMeaPUrZN2uhfCB1XrwHsURZngakYq9Vx" == (std::string)e2p.to);
    CHECK((std::string)e2p.number.to_string() == "5.00000 EVT");

    verify_byte_round_trip_conversion(abis, "evt2pevt", var);
    verify_type_round_trip_conversion<evt2pevt>(abis, "evt2pevt", var);
}

TEST_CASE("everipass_abi_test", "[abis]") {
    auto        abis      = get_evt_abi();
    const char* test_data = R"=======(
    {
        "link": "03XBY4E/KTS:PNHVA3JP9QG258F08JHYOYR5SLJGN0EA-C3J6S:2G:T1SX7WA14KH9ETLZ97TUX9R9JJA6+06$E/_PYNX-/152P4CTC:WKXLK$/7G-K:89+::2K4C-KZ2**HI-P8CYJ**XGFO1K5:$E*SOY8MFYWMNHP*BHX2U8$$FTFI81YDP1HT"
    }
    )=======";

    auto var = fc::json::from_string(test_data);
    auto ep  = var.as<everipass>();

    auto& link = ep.link;

    CHECK(link.get_header() == 3);
    CHECK(*link.get_segment(evt_link::timestamp).intv == 1532465234);
    CHECK(link.get_segment(evt_link::domain).intv.valid() == false);
    CHECK(*link.get_segment(evt_link::domain).strv == "nd1532465232490");
    CHECK(*link.get_segment(evt_link::token).strv == "tk3064930465.8381");

    auto uid = std::string();
    uid.push_back(249);
    uid.push_back(136);
    uid.push_back(100);
    uid.push_back(134);
    uid.push_back(20);
    uid.push_back(86);
    uid.push_back(38);
    uid.push_back(125);
    uid.push_back(124);
    uid.push_back(173);
    uid.push_back(243);
    uid.push_back(124);
    uid.push_back(140);
    uid.push_back(182);
    uid.push_back(117);
    uid.push_back(147);

    CHECK(link.get_segment(evt_link::link_id).strv == uid);

    auto& sigs = link.get_signatures();
    CHECK(sigs.size() == 1);

    CHECK(sigs.find(signature_type(std::string("SIG_K1_JyyaM7x9a4AjaD8yaG6iczgHskUFPvkWEk7X5DPkdZfRGBxYTbpLJ1y7gvmeL4vMqrMmw6QwtErfKUds5L7sxwU2nR7mvu"))) != sigs.end());

    auto pkeys = link.restore_keys();
    CHECK(pkeys.size() == 1);

    CHECK(pkeys.find(public_key_type(std::string("EVT8HdQYD1xfKyD7Hyu2fpBUneamLMBXmP3qsYX6HoTw7yonpjWyC"))) != pkeys.end());
}

TEST_CASE("everipay_abi_test", "[abis]") {
    auto        abis      = get_evt_abi();
    const char* test_data = R"=======(
    {
        "link": "0Q:MMV*39PPS6SQNF74OVVJVIA/W2H:6I4QR6M$-W4HN8VQ421WX_Q/VQG2BWLMWKV73$953S5HR677KCP3G7MYWZMPWYZSN48KW1-2A9PDX1B-RD470*4D1RR*5M*L6HH7/05KW:T51Y*C46D01B",
        "payee": "EVT8HdQYD1xfKyD7Hyu2fpBUneamLMBXmP3qsYX6HoTw7yonpjWyC",
        "number": "5.00000 EVT"
    }
    )=======";

    auto var = fc::json::from_string(test_data);
    auto ep  = var.as<everipay>();

    auto& link = ep.link;

    CHECK(link.get_header() == 5);
    CHECK(*link.get_segment(evt_link::timestamp).intv == 1532582224);
    CHECK(link.get_segment(evt_link::symbol).intv.valid() == false);
    CHECK(*link.get_segment(evt_link::symbol).strv == "5,EVT");
    CHECK(*link.get_segment(evt_link::max_pay).intv == 100000);

    auto uid = std::string();
    uid.push_back(5);
    uid.push_back(219);
    uid.push_back(61);
    uid.push_back(10);
    uid.push_back(255);
    uid.push_back(105);
    uid.push_back(229);
    uid.push_back(118);
    uid.push_back(60);
    uid.push_back(141);
    uid.push_back(100);
    uid.push_back(188);
    uid.push_back(190);
    uid.push_back(201);
    uid.push_back(30);
    uid.push_back(85);

    CHECK(link.get_segment(evt_link::link_id).strv == uid);

    auto& sigs = link.get_signatures();
    CHECK(sigs.size() == 1);

    CHECK(sigs.find(signature_type(std::string("SIG_K1_KmMRWXDnuPJxgvrDMdZdmYApj5QbnAaj3HqiVLkLgwYfwLBcjHuWVZ3gjiLB9DmahxcXs57eazN5Snk7rBtYMk1S9cv6Js"))) != sigs.end());

    auto pkeys = link.restore_keys();
    CHECK(pkeys.size() == 1);

    CHECK(pkeys.find(public_key_type(std::string("EVT8HdQYD1xfKyD7Hyu2fpBUneamLMBXmP3qsYX6HoTw7yonpjWyC"))) != pkeys.end());
}