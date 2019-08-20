#include "contracts_tests.hpp"


TEST_CASE_METHOD(contracts_test, "everipass_test", "[contracts]") {
    auto link   = evt_link();
    auto header = 0;
    header |= evt_link::version1;
    header |= evt_link::everiPass;

    auto head_ts = my_tester->control->head_block_time().sec_since_epoch();

    link.set_header(header);
    link.add_segment(evt_link::segment(evt_link::timestamp, head_ts));
    link.add_segment(evt_link::segment(evt_link::domain, get_domain_name()));
    link.add_segment(evt_link::segment(evt_link::token, "t5"));

    auto ep = everipass();
    ep.link = link;

    auto sign_link = [&](auto& l) {
        l.clear_signatures();
        l.sign(private_key);
    };

    // key of action is not valid
    sign_link(ep.link);
    CHECK_THROWS_AS(my_tester->push_action(action(get_domain_name(), N128(t2), ep), key_seeds, payer), action_authorize_exception);

    // header is not valid
    ep.link.set_header(0);
    sign_link(ep.link);
    CHECK_THROWS_AS(my_tester->push_action(action(get_domain_name(), N128(t5), ep), key_seeds, payer), evt_link_version_exception);

    // type is not valid
    ep.link.set_header(evt_link::version1);
    sign_link(ep.link);
    CHECK_THROWS_AS(my_tester->push_action(action(get_domain_name(), N128(t5), ep), key_seeds, payer), evt_link_type_exception);

    // shoule be everiPass
    ep.link.set_header(evt_link::version1 | evt_link::everiPay);
    sign_link(ep.link);
    CHECK_THROWS_AS(my_tester->push_action(action(get_domain_name(), N128(t5), ep), key_seeds, payer), evt_link_type_exception);

    // timeout
    ep.link.set_header(header);
    ep.link.add_segment(evt_link::segment(evt_link::timestamp, head_ts - 40));
    sign_link(ep.link);
    CHECK_THROWS_AS(my_tester->push_action(action(get_domain_name(), N128(t5), ep), key_seeds, payer), evt_link_expiration_exception);

    // timeout
    ep.link.add_segment(evt_link::segment(evt_link::timestamp, head_ts + 40));
    sign_link(ep.link);
    CHECK_THROWS_AS(my_tester->push_action(action(get_domain_name(), N128(t5), ep), key_seeds, payer), evt_link_expiration_exception);

    // correct
    ep.link.add_segment(evt_link::segment(evt_link::timestamp, head_ts - 5));
    sign_link(ep.link);
    CHECK_NOTHROW(my_tester->push_action(action(get_domain_name(), N128(t5), ep), key_seeds, payer));

    // correct
    ep.link.add_segment(evt_link::segment(evt_link::timestamp, head_ts + 5));
    sign_link(ep.link);
    CHECK_NOTHROW(my_tester->push_action(action(get_domain_name(), N128(t5), ep), key_seeds, payer));

    // because t1 has two owners, here we only provide one
    ep.link.add_segment(evt_link::segment(evt_link::token, "t1"));
    sign_link(ep.link);
    CHECK_THROWS_AS(my_tester->push_action(action(get_domain_name(), N128(t1), ep), key_seeds, payer), everipass_exception);

    // correct
    ep.link.add_segment(evt_link::segment(evt_link::token, "t5"));
    ep.link.add_segment(evt_link::segment(evt_link::timestamp, head_ts));
    sign_link(ep.link);
    CHECK_NOTHROW(my_tester->push_action(action(get_domain_name(), N128(t5), ep), key_seeds, payer));

    // token is not existed
    ep.link.add_segment(evt_link::segment(evt_link::token, "t6"));
    sign_link(ep.link);
    CHECK_THROWS_AS(my_tester->push_action(action(get_domain_name(), N128(t6), ep), key_seeds, payer), unknown_token_exception);

    // destroy token
    header |= evt_link::destroy;
    ep.link.set_header(header);
    ep.link.add_segment(evt_link::segment(evt_link::token, "t5"));
    sign_link(ep.link);
    CHECK_NOTHROW(my_tester->push_action(action(get_domain_name(), N128(t5), ep), key_seeds, payer));

    // token is already destroyed
    ep.link.add_segment(evt_link::segment(evt_link::timestamp, head_ts - 1));
    sign_link(ep.link);
    CHECK_THROWS_AS(my_tester->push_action(action(get_domain_name(), N128(t5), ep), key_seeds, payer), token_destroyed_exception);
}

TEST_CASE_METHOD(contracts_test, "everipay_test", "[contracts]") {
    auto link   = evt_link();
    auto header = 0;
    header |= evt_link::version1;
    header |= evt_link::everiPay;

    auto head_ts = my_tester->control->head_block_time().sec_since_epoch();

    link.set_header(header);
    link.add_segment(evt_link::segment(evt_link::timestamp, head_ts));
    link.add_segment(evt_link::segment(evt_link::max_pay, 50'000'000));  // 500.00000 EVT
    link.add_segment(evt_link::segment(evt_link::symbol_id, evt_sym().id()));
    link.add_segment(evt_link::segment(evt_link::link_id, "KIJHNHFMJDUKJUAB"));

    auto ep   = everipay();
    ep.link   = link;
    ep.payee  = poorer;
    ep.number = asset::from_string("0.00001 S#1");

    auto sign_link = [&](auto& l) {
        l.clear_signatures();
        l.sign(tester::get_private_key(N(payer)));
    };

    // key of action is incorrect(should be 1 for EVT)
    sign_link(ep.link);
    CHECK_THROWS_AS(my_tester->push_action(action(N128(.fungible), N128(2), ep), key_seeds, payer), action_authorize_exception);

    // header is incorrect
    ep.link.set_header(0);
    sign_link(ep.link);
    CHECK_THROWS_AS(my_tester->push_action(action(N128(.fungible), N128(1), ep), key_seeds, payer), evt_link_version_exception);

    // header is incorrect
    ep.link.set_header(evt_link::version1);
    sign_link(ep.link);
    CHECK_THROWS_AS(my_tester->push_action(action(N128(.fungible), N128(1), ep), key_seeds, payer), evt_link_type_exception);

    // header is incorrect, should be everiPay
    ep.link.set_header(evt_link::version1 | evt_link::everiPass);
    sign_link(ep.link);
    CHECK_THROWS_AS(my_tester->push_action(action(N128(.fungible), N128(1), ep), key_seeds, payer), evt_link_type_exception);

    // timeout
    ep.link.set_header(evt_link::version1 | evt_link::everiPay);
    ep.link.add_segment(evt_link::segment(evt_link::timestamp, head_ts - 40));
    sign_link(ep.link);
    CHECK_THROWS_AS(my_tester->push_action(action(N128(.fungible), N128(1), ep), key_seeds, payer), evt_link_expiration_exception);

    // timeout
    ep.link.add_segment(evt_link::segment(evt_link::timestamp, head_ts + 40));
    sign_link(ep.link);
    CHECK_THROWS_AS(my_tester->push_action(action(N128(.fungible), N128(1), ep), key_seeds, payer), evt_link_expiration_exception);

    // not existed
    CHECK_THROWS_AS(my_tester->control->get_link_obj_for_link_id(ep.link.get_link_id()), evt_link_existed_exception);

    // payee is not valid
    ep.link.add_segment(evt_link::segment(evt_link::link_id, "JKHBJKBJKGJHGJAA"));
    ep.link.add_segment(evt_link::segment(evt_link::timestamp, head_ts + 5));
    sign_link(ep.link);
    ep.payee = address(".hi", "test", 123);
    CHECK_THROWS_AS(my_tester->push_action(action(N128(.fungible), N128(1), ep), key_seeds, payer), address_reserved_exception);

    // payee is not valid
    ep.payee = address();
    CHECK_THROWS_AS(my_tester->push_action(action(N128(.fungible), N128(1), ep), key_seeds, payer), address_reserved_exception);

    // correct
    ep.payee = poorer;
    CHECK_NOTHROW(my_tester->push_action(action(N128(.fungible), N128(1), ep), key_seeds, payer));

    // correct
    ep.link.add_segment(evt_link::segment(evt_link::link_id, "KIJHNHFMJDFFUKJU"));
    ep.link.add_segment(evt_link::segment(evt_link::timestamp, head_ts - 5));
    sign_link(ep.link);
    CHECK_NOTHROW(my_tester->push_action(action(N128(.fungible), N128(1), ep), key_seeds, payer));
    link = ep.link;

    // link id is duplicate
    ep.link.add_segment(evt_link::segment(evt_link::timestamp, head_ts));
    ep.link.add_segment(evt_link::segment(evt_link::link_id, "KIJHNHFMJDFFUKJU"));
    sign_link(ep.link);
    CHECK_THROWS_AS(my_tester->push_action(action(N128(.fungible), N128(1), ep), key_seeds, payer), evt_link_dupe_exception);

    // symbol is not correct, should be '5,S#1'
    ep.link.add_segment(evt_link::segment(evt_link::link_id, "JKHBJKBJKGJHGJKG"));
    ep.number = asset::from_string("5.000000 S#1");
    sign_link(ep.link);
    CHECK_THROWS_AS(my_tester->push_action(action(N128(.fungible), N128(1), ep), key_seeds, payer), asset_symbol_exception);

    // correct
    ep.number = asset::from_string("5.00000 S#1");
    sign_link(ep.link);
    CHECK_NOTHROW(my_tester->push_action(action(N128(.fungible), N128(1), ep), key_seeds, payer));

    // exceed max pay: 500.00000 EVT
    ep.link.add_segment(evt_link::segment(evt_link::link_id, "JKHBJKBJKGJHGJET"));
    ep.number = asset::from_string("600.00000 S#1");
    sign_link(ep.link);
    CHECK_THROWS_AS(my_tester->push_action(action(N128(.fungible), N128(1), ep), key_seeds, payer), everipay_exception);

    // cannot use both max_pay and max_pay_str
    ep.link.add_segment(evt_link::segment(evt_link::max_pay_str, "5000"));
    ep.link.add_segment(evt_link::segment(evt_link::link_id, "JKHBJKBJKGJHGJKB"));
    sign_link(ep.link);
    CHECK_THROWS_AS(my_tester->push_action(action(N128(.fungible), N128(1), ep), key_seeds, payer), evt_link_exception);

    // cannot use max pay string here, should be when max pay is large than UINT_MAX
    ep.link.remove_segment(evt_link::max_pay);
    sign_link(ep.link);
    CHECK_THROWS_AS(my_tester->push_action(action(N128(.fungible), N128(1), ep), key_seeds, payer), evt_link_exception);

    // exceed max_pay_str
    ep.link.add_segment(evt_link::segment(evt_link::max_pay_str, "20000000000"));
    ep.number = asset::from_string("400000.00000 S#1");
    sign_link(ep.link);
    CHECK_THROWS_AS(my_tester->push_action(action(N128(.fungible), N128(1), ep), key_seeds, payer), everipay_exception);

    // correct
    ep.number = asset::from_string("1.00000 S#1");
    sign_link(ep.link);
    CHECK_NOTHROW(my_tester->push_action(action(N128(.fungible), N128(1), ep), key_seeds, payer));

    // payer and payee cannot be the same one
    ep.payee = payer;
    ep.link.add_segment(evt_link::segment(evt_link::link_id, "JKHBJKBJKGJHGJKA"));
    sign_link(ep.link);
    CHECK_THROWS_AS(my_tester->push_action(action(N128(.fungible), N128(1), ep), key_seeds, payer), everipay_exception);


    // number and sym id are not match
    ep.number = asset::from_string("500.00000 S#2");
    ep.link.add_segment(evt_link::segment(evt_link::link_id, "JKHBJKBJKGJHGJKE"));
    sign_link(ep.link);
    CHECK_THROWS_AS(my_tester->push_action(action(N128(.fungible), N128(1), ep), key_seeds, payer), everipay_exception);

    ep.link.add_segment(evt_link::segment(evt_link::link_id, "KIJHNHFMJDFFUKJJ"));
    ep.link.add_segment(evt_link::segment(evt_link::fixed_amount, 50000));
    ep.number = asset::from_string("0.50000 S#1");
    ep.payee  = poorer;
    sign_link(ep.link);
    CHECK_NOTHROW(my_tester->push_action(action(N128(.fungible), N128(1), ep), key_seeds, payer));

    ep.link.add_segment(evt_link::segment(evt_link::fixed_amount, 500000));
    ep.link.add_segment(evt_link::segment(evt_link::link_id, "KIJHNHFMJDFFUKJP"));
    sign_link(ep.link);
    CHECK_THROWS_AS(my_tester->push_action(action(N128(.fungible), N128(1), ep), key_seeds, payer), everipay_exception);

    // test everipay ver1
    auto ep_v2   = everipay_v2();
    link.add_segment(evt_link::segment(evt_link::link_id, "KIJHNHFMJDFFUKKK"));
    sign_link(link);
    ep_v2.link   = link;
    ep_v2.payee  = poorer;
    ep_v2.number = asset::from_string("0.00001 S#1");
    ep_v2.memo   = "tttesttt";

    // version not upgrade
    CHECK_THROWS_AS(my_tester->push_action(action(N128(.fungible), N128(1), ep_v2), key_seeds, payer), raw_unpack_exception);

    // correct
    my_tester->control->get_execution_context().set_version(N(everipay), 2);
    CHECK_NOTHROW(my_tester->push_action(action(N128(.fungible), N128(1), ep_v2), key_seeds, payer));

    // restore everiPay version
    my_tester->control->get_execution_context().set_version_unsafe(N(everipay), 0);
}
