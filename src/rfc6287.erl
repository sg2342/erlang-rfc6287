-module(rfc6287).

-type suite() :: binary().
-type challenge() :: binary().
-type counter() :: 0..16#ffffffffffffffff.
-type pin_hash() :: <<_:_*20>> |  <<_:_*32>> |  <<_:_*64>>.
-type ocra() :: binary().
-type key() :: <<_:_*20>> | <<_:_*32>> | <<_:_*40>> | <<_:_*64>> | <<_:_*128>>.
-type counter_window() :: pos_integer().

-type timestep_window() :: pos_integer().
-type session_info() :: binary().
-type timestep() :: <<_:_*8>>.
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
%% Return random challenge [Q] with format and length as specified in
%% [OCRASuite]
%%
-spec challenge(OCRASuite :: suite()) ->
		       {ok, Q :: challenge()} | {error, invalid_suite}.
challenge(Suite) ->
    Maybe = parse(Suite),
    challenge1(Maybe).

challenge1(false) -> {error, invalid_suite};
challenge1({_, DIP}) ->
    {_, F, XX} = lists:keyfind(q, 1, DIP),
    B = crypto:strong_rand_bytes(XX),
    {ok, challenge2(F, B)}.

challenge2($A, B) -> << <<(X rem 93 + $!)>>  || <<X>> <= B >>;
challenge2($N, B) -> << <<(X rem 10 + $0)>>  || <<X>> <= B >>;
challenge2($H, B) -> bin2hex(binary:part(B, 0, size(B) div 2)).


%% @doc
%% Generate [OCRA(K, {\[C\] | Q | \[P | S | T\]})].
%%
-spec generate(K :: key(), data_input()) ->
		      {ok, ocra()} |
		      {error, invalid_suite | invalid_key | invalid_data_input}.
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
%% Verify OCRA Response
-spec verify(key(), data_input(), ocra(),
	     VerifyParams :: #{cw => counter_window()
			      ,tw => timestep_window()}) ->
		    ok | {ok, New_Counter :: counter()} |
		    {error, failed} |
		    {error, invalid_suite | invalid_key | invalid_verify_opts}.
verify(K, #{suite := Suite} = DataInput, OCRA, VerifyOpts) ->
    Maybe = parse(Suite),
    verify1(Maybe, {K, DataInput, OCRA, VerifyOpts}).

verify1(false, _) -> {error, invalid_suite};
verify1({_, DIP} = Parsed, {K, DataInput, OCRA, VerifyOpts}) ->
    Maybe = vopts(DIP, VerifyOpts),
    verify2(Maybe, {Parsed, K, DataInput, OCRA}).

verify2(false, _) -> {error, invalid_verify_opts};
verify2(Vopts, {Parsed, K, DataInput, OCRA}) ->
    {{Alg, _Truncation}, _DIP} = Parsed,
    Maybe = fmt_key(dgst_sz(Alg), K),
    verify3(Maybe, {Parsed, DataInput, OCRA, Vopts}).

verify3(false, _) -> {error, invalid_key};
verify3(K, {Parsed, DataInput, OCRA, Vopts}) ->
    {{_Alg, _Truncation}, DIP} = Parsed,
    Maybe = data(DIP, DataInput),
    verify4(Maybe, {K, Parsed, DataInput, OCRA, Vopts}).

verify4(false, _) -> {error, invalid_data_input};
verify4(Data, {K, {_, DIP} = Parsed, #{t := calc}=DataInput0, OCRA, Vopts}) ->
    {t, V} = lists:keyfind(t,1,DIP),
    DataInput=DataInput0#{t => fmt_ts(V)},
    verify5(Data, K, Parsed, DataInput, OCRA, Vopts);
verify4(Data, {K, Parsed, DataInput, OCRA, Vopts}) ->
    verify5(Data, K, Parsed, DataInput, OCRA, Vopts).


verify5(Data, K, {{Alg, Truncation},_DIP}, _, OCRA, []) ->
    Bin0 = crypto:hmac(Alg, K, Data),
    Bin = truncate(Truncation, Bin0),
    verify_equal(Bin, OCRA);
verify5(Data, K, Parsed, DataInput, OCRA, [{cw, CW}]) ->
    Maybe = ver_check(K, Parsed, Data, OCRA),
    ver_cw(Maybe, K, Parsed, DataInput, OCRA, CW);
verify5(Data, K, Parsed, DataInput, OCRA, [{tw, TW}]) ->
    Maybe = ver_check(K, Parsed, Data, OCRA),
    ver_tw(Maybe, K , Parsed, DataInput, OCRA, TW, 1);
verify5(Data, K, Parsed, DataInput, OCRA, [{tw, TW}, {cw, CW}]) ->
    Maybe = ver_check(K, Parsed, Data, OCRA),
    ver_tw_cw(ver_cw(Maybe, K, Parsed, DataInput, OCRA, CW),
	      K, Parsed, DataInput, OCRA, CW, TW, 1).


ver_check(K, {{Alg, Truncation}, _}, Data, OCRA) ->
    truncate(Truncation, crypto:hmac(Alg, K, Data)) == OCRA.

ver_tw_cw({ok, C}, _, _, _, _, _, _, _) -> {ok, C};
ver_tw_cw({error, failed}, K, {_,DIP} =Parsed, #{t := <<T:64>>} = DataInput,
	  OCRA, CW, TW, TS) when TS < TW ->
    DI0 =DataInput#{t => <<(T + TS):64>>},
    DI1 =DataInput#{t => <<(T + TS):64>>},
    R = case ver_cw(ver_check(K,Parsed, data(DIP, DI0), OCRA),
		    K, Parsed, DI0, OCRA, CW) of
	    {ok, C} -> {ok, C};
	    {error, failed} ->
		ver_cw(ver_check(K, Parsed, data(DIP, DI1), OCRA),
		       K, Parsed, DI1, OCRA, CW)
	end,
    ver_tw_cw(R, K, Parsed, DataInput, OCRA, CW, TW, TS + 1);
ver_tw_cw(_,_,_,_,_,_,_,_) -> {error, failed}.


ver_tw(true, _K, _Parsed, _DataInput, _OCRA, _TW, _TS) -> ok;
ver_tw(false, K, {_, DIP}=Parsed, #{t := <<T:64>>} = DataInput, OCRA, TW, TS)
  when TS < TW ->
    Data0 = data(DIP, DataInput#{t => <<(T + TS):64>>}),
    Data1 = data(DIP, DataInput#{t => <<(T - TS):64>>}),
    Maybe = ver_check(K, Parsed, Data0, OCRA)
	orelse ver_check(K, Parsed, Data1, OCRA),
    ver_tw(Maybe, K, Parsed, DataInput, OCRA, TW, TS + 1);
ver_tw(_, _K, _Parsed, _DataInput,_OCRA,_TW,_T) -> {error, failed}.

ver_cw(true, _K, _Parsed, #{c := C}, _, _) -> {ok, C};
ver_cw(false, K, Parsed, #{c := C} = DataInput0, OCRA, CW) when CW > 0 ->
    {{Alg, Truncation}, DIP} = Parsed,
    DataInput = DataInput0#{c => C + 1},
    Bin = truncate(Truncation, crypto:hmac(Alg, K, data(DIP, DataInput))),
    ver_cw(Bin == OCRA, K, Parsed, DataInput, OCRA, CW - 1);
ver_cw(_, _, _, _, _, _) -> {error, failed}.

verify_equal(A, A) -> ok;
verify_equal(_,_) -> {error, failed}.


%%====================================================================
%% Internal functions
%%====================================================================


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
    case integer_to_binary(Z band 16#7fffffff) of
	B when size(B) < T ->
	    list_to_binary([lists:duplicate(T - size(B), $0), B]);
	B when size(B) > T -> binary:part(B, size(B) - T, T);
	B -> B
    end.


fmt_key(Sz, K) when is_binary(K), size(K) == Sz -> K;
fmt_key(Sz, K) when is_binary(K), Sz * 2 == size(K) -> hex2bin(K);
fmt_key(_, _) -> false.



data(DIP, #{suite := Suite} = DataInput) ->
    L = maps:to_list(maps:remove(suite, DataInput)),
    data1(DIP, L, [0, Suite]).

data1([],[], Acc) -> list_to_binary(lists:reverse(Acc));
data1([V|R], L0, Acc) ->
    MaybeL = lists:keytake(element(1,V), 1, L0),
    data2(MaybeL, V, R, Acc);
data1(_,_,_) -> false.


data2(false, _, _, _) -> false;
data2({value, {_,A}, L}, V, R, Acc) ->
    MaybeF = fmt(V, A),
    data3(MaybeF, R, L, Acc).

data3(false,_,_,_) -> false;
data3(F, R, L, Acc) -> data1(R, L, [F | Acc]).


fmt({c}, C) when is_integer(C), C >= 0, C < 1 bsl 64 -> <<C:64>>;
fmt({q, $A, _}, B) when is_binary(B) ->
    fmt_pad(B);
fmt({q, $H, _}, B0) when is_binary(B0) ->
    try fmt_pad(hex2bin(B0))
    catch error:badarg -> false end;
fmt({q, $N, _}, B0) when is_binary(B0) ->
    try fmt_pad(dec2bin(binary_to_list(B0)))
    catch error:badarg -> false end;
fmt({p, Alg}, B) when is_binary(B) ->
    dgst_sz(Alg) == size(B) andalso B;
fmt({p, Alg}, {pin, B}) when is_binary(B)  -> crypto:hash(Alg, B);
fmt({s, SLen}, B) when is_binary(B), size(B) == SLen -> B;
fmt({t, _}, B) when is_binary(B), size(B) == 8 -> B;
fmt({t, V}, calc) -> fmt_ts(V);
fmt(_,_) -> false.


fmt_pad(B) -> Pad = 128 - size(B), Pad >= 0 andalso <<B/binary, 0:(Pad * 8)>>.

bin2hex(B) -> << <<Y>> || <<X:4>> <= B, Y <- integer_to_list(X, 16) >>.


hex2bin(H) ->
    << <<Z>> || <<X:8, Y:8>> <= H, Z <- [binary_to_integer(<<X, Y>>, 16)] >>.


dec2bin(I) ->
    case integer_to_list(list_to_integer(I), 16) of
	L when length(L) rem 2 == 0 ->
	    hex2bin(list_to_binary(L));
	L -> hex2bin(list_to_binary([L, $0]))
    end.


fmt_ts(Step) ->
    M = calendar,
    Seconds =
	M:datetime_to_gregorian_seconds(M:universal_time()),
    <<(Seconds div Step):64>>.

vopts(DI, #{cw := CW, tw := TW} = VO)
  when is_integer(CW), CW > 0, is_integer(TW), TW > 0 ->
    maps:size(VO) == 2
	andalso   lists:member({c}, DI)
	andalso lists:keymember(t,1,DI)
	andalso [{tw, TW}, {cw, CW}];
vopts(DI, #{cw := CW} = VO) when is_integer(CW), CW > 0 ->
    maps:size(VO) == 1
	andalso lists:member({c}, DI)
	andalso (not lists:keymember(t,1,DI))
	andalso [{cw, CW}];
vopts(DI, #{tw := TW} = VO) when is_integer(TW), TW > 0 ->
    maps:size(VO) == 1
	andalso   lists:keymember(t,1,DI)
	andalso (not lists:member({c}, DI))
	andalso [{tw, TW}];
vopts(DI, #{} = VO) ->
    maps:size(VO) == 0
	andalso (not lists:member({c}, DI))
	andalso (not lists:keymember(t,1,DI))
	andalso [];
vopts(_,_) -> false.
