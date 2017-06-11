-module(rfc6287_SUITE).

-include_lib("common_test/include/ct.hrl").

%%
%% data in test_vector group from "Appendix C. Test Vectors" of OCRA RFC
%% http://tools.ietf.org/html/rfc6287
%%
-define(Key20,
	<<"3132333435363738393031323334353637383930">>).

-define(Key32,
	<<"313233343536373839303132333435363738393031323"
	  "3343536373839303132">>).

-define(Key64,
	<<"313233343536373839303132333435363738393031323"
	  "334353637383930313233343536373839303132333435"
	  "36373839303132333435363738393031323334">>).

-define(Pin, <<"1234">>).

-define(TimeStamp, <<0, 0, 0, 0, 1, 50, 208, 182>>).

-export([all/0, groups/0, end_per_suite/1, init_per_suite/1]).

-export([one_way1/1 ,one_way2/1 ,one_way3/1 ,one_way4/1 ,one_way5/1
	,signature1/1, signature2/1
	,mutual1s/1, mutual1c/1, mutual2s/1, mutual2c/1
	]).

-export([challenge_a/1, challenge_h/1, challenge_n/1, fail_invalid_suite/1,
	 fail_invalid_key/1, fail_invalid_data_input/1,
	 parse_timesteps/1, generate/1]).


groups() ->
    [{test_vector, [parallel],
      [one_way1, one_way2, one_way3, one_way4, one_way5,
       mutual1c, mutual1s, mutual2c, mutual2s, signature1, signature2]}
    ,{coverage, [parallel],
      [challenge_a, challenge_h, challenge_n, fail_invalid_suite,
       fail_invalid_key, fail_invalid_data_input,
       parse_timesteps, generate]}].

all() -> [{group, test_vector}, {group, coverage}].


init_per_suite(Config) ->
    {ok, Apps} = application:ensure_all_started(crypto),
    [{apps_started, Apps}|Config].

end_per_suite(Config) ->
    lists:foreach(fun application:stop/1,
		  lists:reverse(?config(apps_started, Config))),
    lists:keydelete(apps_started, 1, Config).

one_way1(_) ->
    Suite = <<"OCRA-1:HOTP-SHA1-6:QN08">>,
    ct:comment(Suite),
    Rs = [<<"237653">>, <<"243178">>, <<"653583">>, <<"740991">>,
	  <<"608993">>, <<"388898">>, <<"816933">>, <<"224598">>,
	  <<"750600">>, <<"294470">>],
    Qs = [list_to_binary(lists:duplicate(8, $0 + N)) || N <- lists:seq(0, 9)],
    L = [rfc6287:generate(?Key20, #{suite => Suite, q => Q}) || Q <- Qs],
    {_, Rs} = lists:unzip(L).

one_way2(_) ->
    Suite = <<"OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1">>,
    ct:comment(Suite),
    Rs = [<<"65347737">>, <<"86775851">>, <<"78192410">>, <<"71565254">>,
	  <<"10104329">>, <<"65983500">>, <<"70069104">>, <<"91771096">>,
	  <<"75011558">>, <<"08522129">>],
    Q = <<"12345678">>,
    Cs = lists:seq(0,9),
    DI = #{suite => Suite, q => Q, p => {pin, ?Pin}},
    L = [rfc6287:generate(?Key32, DI#{c => C}) || C <- Cs],
    {_, Rs} = lists:unzip(L).

one_way3(_) ->
    Suite = <<"OCRA-1:HOTP-SHA256-8:QN08-PSHA1">>,
    ct:comment(Suite),
    Qs = [list_to_binary(lists:duplicate(8, $0 + N)) || N <- lists:seq(0,4)],
    Rs = [<<"83238735">>, <<"01501458">>, <<"17957585">>, <<"86776967">>,
	  <<"86807031">>],
    DI = #{suite => Suite, p => {pin, ?Pin}},
    L = [rfc6287:generate(?Key32, DI#{q => Q}) || Q <- Qs],
    {_, Rs} = lists:unzip(L).

one_way4(_) ->
    Suite = <<"OCRA-1:HOTP-SHA512-8:C-QN08">>,
    ct:comment(Suite),
    Rs = [<<"07016083">>, <<"63947962">>, <<"70123924">>, <<"25341727">>,
	  <<"33203315">>, <<"34205738">>, <<"44343969">>, <<"51946085">>,
	  <<"20403879">>, <<"31409299">>],
    CQs = [{N, list_to_binary(lists:duplicate(8, $0 + N))}
	   || N <- lists:seq(0,9)],
    DI = #{suite => Suite},
    L = [rfc6287:generate(?Key64, DI#{c => C, q => Q}) || {C, Q} <- CQs],
    {_, Rs} = lists:unzip(L).

one_way5(_) ->
    Suite = <<"OCRA-1:HOTP-SHA512-8:QN08-T1M">>,
    ct:comment(Suite),
    Rs = [<<"95209754">>, <<"55907591">>, <<"22048402">>, <<"24218844">>,
	  <<"36209546">>],
    Qs = [list_to_binary(lists:duplicate(8, $0 + N)) || N <- lists:seq(0, 4)],
    DI = #{suite => Suite, t => ?TimeStamp},
    L = [rfc6287:generate(?Key64, DI#{q => Q}) || Q <- Qs],
    {_, Rs} = lists:unzip(L).

signature1(_) ->
    Suite = <<"OCRA-1:HOTP-SHA256-8:QA08">>,
    ct:comment(Suite),
    Rs = [<<"53095496">>, <<"04110475">>, <<"31331128">>, <<"76028668">>,
	  <<"46554205">>],
    Qs = [<<"SIG10000">>, <<"SIG11000">>, <<"SIG12000">>, <<"SIG13000">>,
	  <<"SIG14000">>],
    DI = #{suite => Suite},
    L = [rfc6287:generate(?Key32, DI#{q => Q}) || Q <- Qs],
    {_, Rs} = lists:unzip(L).

signature2(_) ->
    Suite = <<"OCRA-1:HOTP-SHA512-8:QA10-T1M">>,
    ct:comment(Suite),
    Rs = [<<"77537423">>, <<"31970405">>, <<"10235557">>, <<"95213541">>,
	  <<"65360607">>],
    Qs = [<<"SIG1000000">>, <<"SIG1100000">>, <<"SIG1200000">>,
	  <<"SIG1300000">>, <<"SIG1400000">>],
    DI = #{suite => Suite, t => ?TimeStamp},
    L = [rfc6287:generate(?Key64, DI#{q => Q}) || Q <- Qs],
    {_, Rs} = lists:unzip(L).

mutual1s(_) ->
    Suite = <<"OCRA-1:HOTP-SHA256-8:QA08">>,
    ct:comment({Suite, "(server computation)"}),
    Rs = [<<"28247970">>, <<"01984843">>, <<"65387857">>, <<"03351211">>,
	  <<"83412541">>],
    Qs = [<<"CLI22220SRV11110">>, <<"CLI22221SRV11111">>,
	  <<"CLI22222SRV11112">>, <<"CLI22223SRV11113">>,
	  <<"CLI22224SRV11114">>],
    DI = #{suite => Suite},
    L = [rfc6287:generate(?Key32, DI#{q => Q}) || Q <- Qs],
    {_, Rs} = lists:unzip(L).

mutual1c(_) ->
    Suite = <<"OCRA-1:HOTP-SHA256-8:QA08">>,
    ct:comment({Suite, "(client computation)"}),
    Rs = [<<"15510767">>, <<"90175646">>, <<"33777207">>, <<"95285278">>,
	  <<"28934924">>],
    Qs = [<<"SRV11110CLI22220">>, <<"SRV11111CLI22221">>,
	  <<"SRV11112CLI22222">>, <<"SRV11113CLI22223">>,
	  <<"SRV11114CLI22224">>],
    DI = #{suite => Suite},
    L = [rfc6287:generate(?Key32, DI#{q => Q}) || Q <- Qs],
    {_, Rs} = lists:unzip(L).

mutual2s(_) ->
    Suite = <<"OCRA-1:HOTP-SHA512-8:QA08">>,
    ct:comment({Suite, "(server computation)"}),
    Rs = [<<"79496648">>, <<"76831980">>, <<"12250499">>, <<"90856481">>,
	  <<"12761449">>],
    Qs = [<<"CLI22220SRV11110">>, <<"CLI22221SRV11111">>,
	  <<"CLI22222SRV11112">>, <<"CLI22223SRV11113">>,
	  <<"CLI22224SRV11114">>],
    DI = #{suite => Suite},
    L = [rfc6287:generate(?Key64, DI#{q => Q}) || Q <- Qs],
    {_, Rs} = lists:unzip(L).

mutual2c(_) ->
    Suite = <<"OCRA-1:HOTP-SHA512-8:QA08-PSHA1">>,
    ct:comment({Suite, " (client computation)"}),
    Rs= [<<"18806276">>, <<"70020315">>, <<"01600026">>, <<"18951020">>,
	 <<"32528969">>],
    Qs = [<<"SRV11110CLI22220">>, <<"SRV11111CLI22221">>,
	  <<"SRV11112CLI22222">>, <<"SRV11113CLI22223">>,
	  <<"SRV11114CLI22224">>],
    DI = #{suite => Suite, p => {pin, ?Pin}},
    L = [rfc6287:generate(?Key64, DI#{q => Q}) || Q <- Qs],
    {_, Rs} = lists:unzip(L).

challenge_a(_) ->
    Suite = <<"OCRA-1:HOTP-SHA512-8:QA08-PSHA1">>,
    {ok, Q} = rfc6287:challenge(Suite),
    ct:comment({Suite, " challenge :", Q}).

challenge_h(_) ->
    Suite = <<"OCRA-1:HOTP-SHA512-0:C-QH16-T14H">>,
    {ok, Q} = rfc6287:challenge(Suite),
    ct:comment({Suite, " challenge :", Q}).

challenge_n(_) ->
    Suite = <<"OCRA-1:HOTP-SHA256-0:QN10">>,
    {ok, Q} = rfc6287:challenge(Suite),
    ct:comment({Suite, " challenge :", Q}).


fail_invalid_suite(_) ->
    E = {error, invalid_suite},
    E = rfc6287:generate(?Key64, #{suite => "not_binary"}),
    E = rfc6287:challenge(<<"does not start with OCRA-1">>),
    E = rfc6287:challenge(<<"OCRA-1:not HOTP:ffoo">>),
    E = rfc6287:challenge(<<"OCRA-1:HOTP-SHA512-1:fff">>),
    E = rfc6287:challenge(<<"OCRA-1:HOTP-SHA512-19999:fff">>),
    E = rfc6287:challenge(<<"OCRA-1:HOTP-SHX-8:QA08">>),
    E = rfc6287:challenge(<<"OCRA-1:HOTP-SHA512-8:QA99">>),
    E = rfc6287:challenge(<<"OCRA-1:HOTP-SHA512-8:QA08-Pfoo">>),
    E = rfc6287:challenge(<<"OCRA-1:HOTP-SHA512-8:QA08-Sabd">>),
    E = rfc6287:challenge(<<"OCRA-1:HOTP-SHA512-8:QA08-S123-T-foo">>),
    E = rfc6287:challenge(<<"OCRA-1:HOTP-SHA512-8:QA08-S123-T999H">>),
    E = rfc6287:challenge(<<"OCRA-1:HOTP-SHA512-8:QA08-S123-T99H">>).

parse_timesteps(_) ->
    ct:comment("parse various timesteps"),
    {ok, _} = rfc6287:challenge(<<"OCRA-1:HOTP-SHA512-8:QA08-T">>),
    {ok, _} = rfc6287:challenge(<<"OCRA-1:HOTP-SHA512-8:QA08-T1S">>),
    {ok, _} = rfc6287:challenge(<<"OCRA-1:HOTP-SHA512-8:QA08-T12S">>),
    {ok, _} = rfc6287:challenge(<<"OCRA-1:HOTP-SHA512-8:QA08-T1M">>),
    {ok, _} = rfc6287:challenge(<<"OCRA-1:HOTP-SHA512-8:QA08-T12M">>),
    {ok, _} = rfc6287:challenge(<<"OCRA-1:HOTP-SHA512-8:QA08-T1H">>),
    {ok, _} = rfc6287:challenge(<<"OCRA-1:HOTP-SHA512-8:QA08-T12H">>).

fail_invalid_key(_) ->
    {error, invalid_key} =
	rfc6287:generate(<<>>, #{suite => <<"OCRA-1:HOTP-SHA512-8:QA08-T">>}).

fail_invalid_data_input(_) ->
    E = {error, invalid_data_input},
    K = ?Key32,
    E = rfc6287:generate(K, #{suite => <<"OCRA-1:HOTP-SHA256-8:QA08-T">>}),
    E = rfc6287:generate(K, #{suite => <<"OCRA-1:HOTP-SHA256-8:QA08">>
			     ,q => <<"12345678">>
			     ,somthing_unexpectd => true}),
    E = rfc6287:generate(K, #{suite => <<"OCRA-1:HOTP-SHA256-8:QH08">>
			     ,q => <<"________">>}),
    E = rfc6287:generate(K, #{suite => <<"OCRA-1:HOTP-SHA256-8:QN08">>
			     ,q => <<"________">>}),
    E = rfc6287:generate(K, #{suite => <<"OCRA-1:HOTP-SHA256-8:QA08-PSHA1">>
			     ,q => <<"12345678">>
			     ,p => <<>>}),
    E = rfc6287:generate(K, #{suite => <<"OCRA-1:HOTP-SHA256-8:QA08-PSHA1">>
			     ,q => <<"12345678">>
			     ,p => <<>>}),
    E = rfc6287:generate(K, #{suite => <<"OCRA-1:HOTP-SHA256-8:QA08-S001">>
			     ,q => <<"12345678">>
			     ,p => <<"123too long">>}),

    E = rfc6287:generate(K, #{suite => <<"OCRA-1:HOTP-SHA256-8:QA08-S001-T">>
			     ,q => <<"12345678">>
			     ,s => <<"0">>
			     ,t => something}),

    ok.


generate(_) ->
    %% pad in truncate
    {ok, <<"0958035737">>} =
	rfc6287:generate(?Key20,
			 #{suite => <<"OCRA-1:HOTP-SHA1-10:QH08">>
			  ,q => <<"D0DD18F3">>}),
    %% calc timestamp
    {ok, _} = rfc6287:generate(?Key32,
			       #{suite => <<"OCRA-1:HOTP-SHA512-0:C-QA08-T">>
				,c => 0
				,q => <<"000000">>
				,t => calc
				}).
