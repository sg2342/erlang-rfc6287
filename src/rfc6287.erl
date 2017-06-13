%%% @author Stefan Grundmann <sg2342@googlemail.com>
%%% @reference <a href="http://tools.ietf.org/html/rfc6287">RFC6287</a>
%%% @reference <a href="http://www.rfc-editor.org/errata_search.php?eid=3729">
%%% RFC Errata ID: 3729</a>
%%% @doc RFC6287 OCRA (OATH Challenge-Response Algorithm)
%%%
%%% given
%%% ```Suite = <<"OCRA-1:HOTP-SHA1-6:C-QN08-PSHA1">>.'''
%%%
%%% challenge `Q' for `Suite':
%%% ```{ok, Q} = rfc6287:challenge(Suite).'''
%%%
%%% generate `OCRA' for key `K', challenge `Q', counter `C=23' and
%%% Pin `<<"1234">>':
%%%
%%% ```
%%%    Pin = <<"1234">>,
%%%    K = <<"00112233445566778899aabbccddeeff00112233">>,
%%%    DI_client = #{suite => Suite, q => Q, c => 23, p => {pin, Pin}},
%%%    {ok, OCRA} = rfc6287:generate(K, DI_client). '''
%%%
%%% verify `OCRA' for key `K', challenge `Q' and `PinHash' using
%%% `C=20' as staring counter and a counter_window of `10'
%%% ```
%%%    PinHash = crypto:sha(Pin),
%%%    DI_server = #{suite => Suite, q => Q, c => 20, p => PinHash},
%%%    {ok, NextCounter} = rfc6287:verify(K, DI_server, OCRA, #{cw => 10}).
%%% '''
%%%
%%% `NextCounter' is `24'
%%%
-module(rfc6287).

-type suite() :: binary().
%% `OCRASuite' string

-type counter() :: 0..16#ffffffffffffffff.
%% DataInput parameter `C'

-type challenge() :: binary().
%% OCRA challenge string, output of {@link challenge/1.}
%% DataInput parameter `Q'


-type pin_hash() :: <<_:_*20>> |  <<_:_*32>> |  <<_:_*64>>.
%% DataInput parameter `P'

-type session_info() :: binary().
%% DataInput parameter `S'

-type timestep() :: <<_:_*8>>.
%% DataInput parameter `T'

-type ocra() :: binary().
%% OCRA result, output of {@link generate/2.}

-type key() :: <<_:_*20>> | <<_:_*32>> | <<_:_*40>> | <<_:_*64>> | <<_:_*128>>.
%% `K', either hexadecimal binary string or binary.

-type counter_window() :: pos_integer().

-type timestep_window() :: pos_integer().


-type data_input() :: #{suite := suite()
                       ,c => counter()
                       ,q := challenge()
		       ,p => {pin, binary()} | pin_hash()
		       ,s => session_info()
		       ,t => timestep() | calc}.

-type dgst() :: sha | sha256 | sha512.
-type data_input_parsed() ::
	[{c} |
	 {q, $A | $N | $H, 4..64} |
	 {p, dgst()} |
	 {s, 0..999} |
	 {t, pos_integer()}].

-export_type([suite/0, challenge/0, counter/0, pin_hash/0, ocra/0, key/0,
	      session_info/0, timestep/0, data_input/0]).

-export_type([timestep_window/0, counter_window/0]).


%% API exports
-export([challenge/1, generate/2, verify/4]).


%%====================================================================
%% API functions
%%====================================================================

%% @doc
%% Create random challenge() with format and length as specified in
%% `OCRASuite'.
%% @returns <dl>
%%          <dt>`{ok, challenge()}'</dt>
%%          <dt>`{error, invalid_suite}' if `OCRASuite'
%%               is not a valid suite</dt>
%%          </dl>
-spec challenge(OCRASuite :: suite()) ->
		       {ok, Q :: challenge()} | {error, invalid_suite}.
challenge(Suite) ->
    Maybe = parse(Suite),
    challenge1(Maybe).

challenge1(false) -> {error, invalid_suite};
challenge1({_, DIP}) ->
    {_, F, XX} = lists:keyfind(q, 1, DIP),
    Bin = crypto:strong_rand_bytes(XX),
    {ok, challenge2(F, Bin)}.

challenge2($A, B) -> << <<(X rem 93 + $!)>>  || <<X>> <= B >>;
challenge2($N, B) -> << <<(X rem 10 + $0)>>  || <<X>> <= B >>;
challenge2($H, B) -> bin2hex(binary:part(B, 0, size(B) div 2)).


%% @doc
%% Generate `OCRA(K, {[C] | Q | [P | S | T]})'.
%% @returns <dl>
%%          <dt>`{ok, ocra()}'</dt>
%%          <dt>`{error, invalid_suite}' if suite in `DataInput' is
%%               not a valid OCRA suite</dt>
%%          <dt>`{error, invalid_key}' if `K' is not of the size
%%               required by suite in `DataInput' or if `K' is twice the size
%%               required by suite and but not a hex string.</dt>
%%          <dt>`{error, invalid_data_input}' if DataInput is missing keys,
%%               has to many keys or values not conforming to suite</dt>
%%          </dl>
-spec generate(K :: key(), data_input()) ->
		      {ok, ocra()} |
		      {error,
		       invalid_suite | invalid_key | invalid_data_input}.
generate(K, #{suite := Suite} = DataInput) ->
    Maybe = parse(Suite),
    generate1(Maybe, {K, DataInput}).

generate1(false, _) -> {error, invalid_suite};
generate1({{Alg, _Truncation}, _DI} = Parsed, {K, DataInput}) ->
    Maybe = fmt_key(dgst_sz(Alg), K),
    generate2(Maybe, {Parsed, DataInput}).

generate2(false, _) -> {error, invalid_key};
generate2(Key, {{{Alg, Truncation}, DIP}, DataInput}) ->
    Maybe = data(DIP, DataInput),
    generate3(Maybe, {Key, Alg, Truncation}).

generate3(false, _) -> {error, invalid_data_input};
generate3(Data, {Key, Alg, Truncation}) ->
    Bin = crypto:hmac(Alg, Key, Data),
    {ok, truncate(Truncation, Bin)}.


%% @doc
%% Verify `OCRA' response.
%% @returns <dl>
%%          <dt>`ok' - success</dt>
%%          <dt>`{ok, NextCounter :: counter()}' - success, suite specified
%%               a `C' parameter</dt>
%%          <dt>`{error, failed}' - failure to verify `OCRA'</dt>
%%          <dt>`{error, invalid_suite}' if suite in `DataInput' is
%%               not a valid OCRA suite</dt>
%%          <dt>`{error, invalid_key}' if `K' is not of the size
%%               required by suite in `DataInput' or if `K' is twice the size
%%               required by suite and but not a hex string.</dt>
%%          <dt>`{error, invalid_data_input}' if DataInput is missing keys,
%%               has to many keys or values not conforming to suite</dt>
%%          <dt>`{error, invalid_parameters}' if `VerifyParams' is not
%%               consistent (e.g. suite has `T' DataInput parameter, but
%%               `VerifyParams' has no `tw' key)</dt>
%%          </dl>
-spec verify(key(), data_input(), ocra(),
	     #{cw => counter_window() ,tw => timestep_window()}) ->
		    ok | {ok, New_Counter :: counter()} |
		    {error, failed} |
		    {error, invalid_suite | invalid_key | invalid_parameters}.
verify(K, #{suite := Suite} = DataInput, OCRA, VerifyParams) ->
    Maybe = parse(Suite),
    verify1(Maybe, {K, DataInput, OCRA, VerifyParams}).

verify1(false, _) -> {error, invalid_suite};
verify1({_, DIP} = Parsed, {K, DataInput, OCRA, VerifyParams}) ->
    Maybe = vpar(DIP, VerifyParams),
    verify2(Maybe, {Parsed, K, DataInput, OCRA}).

verify2(false, _) -> {error, invalid_parameters};
verify2(Vpar, {Parsed, K, DataInput, OCRA}) ->
    {{Alg, _Truncation}, _DIP} = Parsed,
    Maybe = fmt_key(dgst_sz(Alg), K),
    verify3(Maybe, {Parsed, DataInput, OCRA, Vpar}).

verify3(false, _) -> {error, invalid_key};
verify3(K, {Parsed, DataInput, OCRA, Vpar}) ->
    {{_Alg, _Truncation}, DIP} = Parsed,
    Maybe = data(DIP, DataInput),
    verify4(Maybe, {K, Parsed, DataInput, OCRA}, Vpar).

verify4(false, _, _) -> {error, invalid_data_input};
verify4(Data, {K, {_, DIP} = Parsed, #{t := calc} = DataInput0, OCRA}, Vpar) ->
    {t, V} = lists:keyfind(t, 1, DIP),
    DataInput = DataInput0#{t => fmt_ts(V)},
    verify5(Data, {K, Parsed, DataInput, OCRA}, Vpar);
verify4(Data, Y, Vpar) -> verify5(Data, Y, Vpar).


verify5(Data, {K, {{Alg, Truncation}, _DIP}, _, OCRA}, []) ->
    Bin0 = crypto:hmac(Alg, K, Data),
    Bin = truncate(Truncation, Bin0),
    verify_equal(Bin, OCRA);
verify5(Data, {K, Parsed, _, OCRA} = Y, [{cw, CW}]) ->
    Maybe = ver_check({K, Parsed, Data, OCRA}),
    ver_cw(Maybe, Y, CW);
verify5(Data, {K, Parsed, _, OCRA} = Y, [{tw, TW}]) ->
    Maybe = ver_check({K, Parsed, Data, OCRA}),
    ver_tw(Maybe, Y, TW, 1);
verify5(Data, {K, Parsed, _, OCRA} = Y, [{tw, TW}, {cw, CW}]) ->
    Maybe = ver_check({K, Parsed, Data, OCRA}),
    ver_tw_cw(ver_cw(Maybe, Y, CW), Y, CW, TW, 1).


%%====================================================================
%% Internal functions
%%====================================================================

ver_check({K, {{Alg, Truncation}, _}, Data, OCRA}) when is_binary(Data) ->
    OCRA == truncate(Truncation, crypto:hmac(Alg, K, Data));
ver_check({K, {_, DIP} = Parsed, DataInput, OCRA}) ->
    Data = data(DIP, DataInput),
    ver_check({K, Parsed, Data, OCRA}).


ver_tw_cw({ok, NextC}, _, _, _, _) -> {ok, NextC};
ver_tw_cw({error, failed}, {K, Parsed, #{t := <<T:64>>} = DataInput, OCRA},
	  CW, TW, TS) when TS < TW ->
    Past = {K, Parsed, DataInput#{t => <<(T - TS):64>>}, OCRA},
    Future = {K, Parsed, DataInput#{t => <<(T + TS):64>>}, OCRA},
    MaybeOk = ver_cw(ver_check(Past), Past, CW),
    R = ver_tw_cw1(MaybeOk, Future, CW),
    ver_tw_cw(R, {K, Parsed, DataInput, OCRA}, CW, TW, TS + 1);
ver_tw_cw(_, _, _, _, _) -> {error, failed}.

ver_tw_cw1({ok, C}, _, _) -> {ok, C};
ver_tw_cw1({error, failed}, Future, CW) ->
    ver_cw(ver_check(Future), Future, CW).


ver_tw(true, _, _, _) -> ok;
ver_tw(false, {K, Parsed, #{t := <<T:64>>} = DataInput, OCRA}, TW, TS)
  when TS < TW ->
    Past = {K, Parsed, DataInput#{t => <<(T - TS):64>>}, OCRA},
    Future = {K, Parsed, DataInput#{t => <<(T + TS):64>>}, OCRA},
    Maybe = ver_check(Past) orelse ver_check(Future),
    ver_tw(Maybe, {K, Parsed, DataInput, OCRA}, TW, TS + 1);
ver_tw(_, _, _, _) -> {error, failed}.


ver_cw(true, {_K, _Parsed, #{c := C}, _}, _) ->
    {ok, (C + 1) band 16#ffffffffffffffff};
ver_cw(false, {K, Parsed, #{c := C} = DataInput, OCRA}, CW) when CW > 0 ->
    Next = {K, Parsed, DataInput#{c => C + 1}, OCRA},
    Maybe = ver_check(Next),
    ver_cw(Maybe, Next, CW - 1);
ver_cw(_, _, _) -> {error, failed}.


verify_equal(A, A) -> ok;
verify_equal(_,_) -> {error, failed}.


-spec parse(suite()) ->
		   {{dgst(), Truncation :: false | 4..10},
		    data_input_parsed()} | false.
parse(Suite) when is_binary(Suite) ->
    parse1(string:tokens(binary_to_list(Suite), ":"));
parse(_) -> false.

parse1(["OCRA-1", C, DI]) -> parse2(string:tokens(C, "-"), DI);
parse1(_) -> false.

parse2(["HOTP", A, T], DI) -> parse3(p_len(T, 0, 10), A, DI);
parse2(_,_) -> false.

parse3(0, A, DI) ->
    parse4(p_di(string:tokens(DI, "-")), false, A);
parse3(X, A, DI) when X > 3 ->
    parse4(p_di(string:tokens(DI, "-")), X, A);
parse3(_, _, _) -> false.

parse4(false, _, _) -> false;
parse4(DIP, Truncation, Alg) -> parse5(dgst(Alg), Truncation, DIP).

parse5(false, _, _) -> false;
parse5(Alg, Truncation, DIP) -> {{Alg, Truncation}, DIP}.

p_di(["C" | R]) -> p_di_q(R, [{c}]);
p_di(R) -> p_di_q(R, []).

p_di_q([[$Q, QT | [_, _] = QLen] | R], Acc)
  when QT == $A; QT == $N; QT == $H ->
    p_di_q1(p_len(QLen, 4, 64), QT, R, Acc);
p_di_q(_,_) -> false.

p_di_q1(false, _, _, _) -> false;
p_di_q1(QL, QT, R, Acc) -> p_di_p(R, [{q, QT, QL} | Acc]).

p_di_p([[$P | Alg] | R], Acc) -> p_di_p1(dgst(Alg), R, Acc);
p_di_p(R, Acc) -> p_di_s(R, Acc).

p_di_p1(false, _, _) -> false;
p_di_p1(Alg, R, Acc) -> p_di_s(R, [{p, Alg} | Acc]).

p_di_s([[$S | [_,_,_] = N] | R], Acc) -> p_di_s1(p_len(N, 0, 999), R, Acc);
p_di_s(R, Acc) -> p_di_ts(R, Acc).

p_di_s1(false, _, _) -> false;
p_di_s1(SLen, R, Acc) -> p_di_ts(R, [{s, SLen} | Acc]).

p_di_ts([], Acc) -> lists:reverse(Acc);
p_di_ts([[$T| G]], Acc) -> p_di_ts1(p_di_ts2(G), Acc);
p_di_ts(_, _) -> false.

p_di_ts1(false, _) -> false;
p_di_ts1(TS, Acc) -> lists:reverse([{t, TS}| Acc]).

p_di_ts2([]) -> 60;
p_di_ts2([X, $S]) -> p_len([X], 1, 59);
p_di_ts2([X1, X2, $S]) -> p_len([X1, X2], 1, 59);
p_di_ts2([X, $M]) -> p_di_ts3(p_len([X], 1, 59), 60);
p_di_ts2([X1, X2, $M]) -> p_di_ts3(p_len([X1, X2], 1, 59), 60);
p_di_ts2([X, $H]) -> p_di_ts3(p_len([X], 1, 59), 60);
p_di_ts2([X1, X2, $H]) -> p_di_ts3(p_len([X1, X2], 0, 48), 3600);
p_di_ts2(_) -> false.

p_di_ts3(false,_) -> false;
p_di_ts3(X, Y) -> X * Y.

p_len(S, Min, Max) ->
    try plen1(list_to_integer(S), Min, Max) catch error:badarg -> false end.

plen1(L, Min, Max) when L >= Min, L =< Max -> L;
plen1(_,_,_) -> false.


dgst_sz(sha) -> 20;
dgst_sz(sha256) -> 32;
dgst_sz(sha512) -> 64.


dgst("SHA1") -> sha;
dgst("SHA256") -> sha256;
dgst("SHA512") -> sha512;
dgst(_) -> false.


truncate(false, Bin) -> Bin;
truncate(T, Bin) ->
    Offset = binary:last(Bin) band 16#0f,
    <<_:Offset/binary, Z:32, _/binary>> = Bin,
    truncate1(integer_to_binary(Z band 16#7fffffff), T).

truncate1(B, T) when size(B) < T ->
    list_to_binary([lists:duplicate(T - size(B), $0), B]);
truncate1(B, T) when size(B) > T -> binary:part(B, size(B) - T, T);
truncate1(B, _) -> B.

%% ensure Key consistent with size from parsed suite,
%% also handle hexadecimal keys
fmt_key(Sz, K) when is_binary(K), size(K) == Sz -> K;
fmt_key(Sz, K) when is_binary(K), Sz * 2 == size(K) ->
    try hex2bin(K) catch error:badarg -> false end;
fmt_key(_, _) -> false.


%% create DataInput binary, ensure DataIput
%% consistent with parsed suite.
data(DIP, #{suite := Suite} = DataInput) ->
    L = maps:to_list(maps:remove(suite, DataInput)),
    data1(DIP, L, [0, Suite]).

data1([],[], Acc) -> list_to_binary(lists:reverse(Acc));
data1([V|R], L0, Acc) ->
    MaybeL = lists:keytake(element(1,V), 1, L0),
    fmt(MaybeL, V, R, Acc);
data1(_,_,_) -> false.


fmt(false, _, _, _) -> false;
fmt({value, {_, A}, L}, V, R, Acc) ->
    fmt2(fmt1(V, A), R, L, Acc).

fmt1({c}, C) when is_integer(C), C >= 0, C < 1 bsl 64 -> <<C:64>>;
fmt1({q, $A, _}, B) when is_binary(B) ->
    fmt_pad(B);
fmt1({q, $H, _}, B0) when is_binary(B0) ->
    try fmt_pad(hex2bin(B0))
    catch error:badarg -> false end;
fmt1({q, $N, _}, B0) when is_binary(B0) ->
    try fmt_pad(dec2bin(binary_to_list(B0)))
    catch error:badarg -> false end;
fmt1({p, Alg}, B) when is_binary(B) ->
    dgst_sz(Alg) == size(B) andalso B;
fmt1({p, Alg}, {pin, B}) when is_binary(B)  -> crypto:hash(Alg, B);
fmt1({s, SLen}, B) when is_binary(B), size(B) == SLen -> B;
fmt1({t, _}, B) when is_binary(B), size(B) == 8 -> B;
fmt1({t, V}, calc) -> fmt_ts(V);
fmt1(_,_) -> false.

fmt2(false,_,_,_) -> false;
fmt2(F, R, L, Acc) -> data1(R, L, [F | Acc]).


fmt_pad(B) -> Pad = 128 - size(B), Pad >= 0 andalso <<B/binary, 0:(Pad * 8)>>.


bin2hex(B) -> << <<Y>> || <<X:4>> <= B, Y <- integer_to_list(X, 16) >>.


hex2bin(H) ->
    << <<Z>> || <<X:8, Y:8>> <= H, Z <- [binary_to_integer(<<X, Y>>, 16)] >>.


dec2bin(I) -> dec2bin1(integer_to_list(list_to_integer(I), 16)).

dec2bin1(L) when length(L) rem 2 == 0 -> hex2bin(list_to_binary(L));
dec2bin1(L) -> hex2bin(list_to_binary([L, $0])).


fmt_ts(Step) ->
    M = calendar,
    Seconds = M:datetime_to_gregorian_seconds(M:universal_time()),
    <<(Seconds div Step):64>>.


%% ensure VerifyParams consistent with parsed suite.
vpar(DI, #{cw := CW, tw := TW} = M)
  when is_integer(CW), CW > 0, is_integer(TW), TW > 0 ->
    maps:size(M) == 2
	andalso   lists:member({c}, DI)
	andalso lists:keymember(t,1,DI)
	andalso [{tw, TW}, {cw, CW}];
vpar(DI, #{cw := CW} = M) when is_integer(CW), CW > 0 ->
    maps:size(M) == 1
	andalso lists:member({c}, DI)
	andalso (not lists:keymember(t,1,DI))
	andalso [{cw, CW}];
vpar(DI, #{tw := TW} = M) when is_integer(TW), TW > 0 ->
    maps:size(M) == 1
	andalso   lists:keymember(t,1,DI)
	andalso (not lists:member({c}, DI))
	andalso [{tw, TW}];
vpar(DI, #{} = M) ->
    maps:size(M) == 0
	andalso (not lists:member({c}, DI))
	andalso (not lists:keymember(t,1,DI))
	andalso [];
vpar(_,_) -> false.
