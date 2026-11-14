-module(certlint_tests).
-include_lib("eunit/include/eunit.hrl").

today() -> {2026, 11, 14}.
run(File, Today) -> {_, Fs} = certlint:lint_path("examples/certs/" ++ File, Today), Fs.
rules(Fs) -> lists:usort([R || {_, R, _, _} <- Fs]).
has(Fs, Rule, Sev) -> lists:any(fun({S, R, _, _}) -> S =:= Sev andalso R =:= Rule end, Fs).

parse_date_test() ->
    ?assertEqual({2026, 1, 31}, certlint:parse_date("2026-01-31")),
    ?assertError(_, certlint:parse_date("2026-02-30")),
    ?assertError(_, certlint:parse_date("nope")).
severity_rank_test() ->
    ?assert(certlint:severity_rank(critical) < certlint:severity_rank(high)),
    ?assert(certlint:severity_rank(high) < certlint:severity_rank(medium)),
    ?assert(certlint:severity_rank(medium) < certlint:severity_rank(low)).
good_cert_only_quantum_test() ->
    ?assertEqual(["CERT007"], rules(run("good.pem", today()))).
weak_rsa_test() ->
    Fs = run("weak-rsa.pem", today()),
    ?assert(has(Fs, "CERT002", high)).
sha1_test() -> ?assert(has(run("sha1-signed.pem", today()), "CERT003", high)).
no_san_test() ->
    Fs = run("no-san.pem", today()),
    ?assert(has(Fs, "CERT005", high)),
    ?assert(has(Fs, "CERT004", medium)).
wildcard_ec_test() ->
    Fs = run("wildcard-ec.pem", today()),
    ?assert(has(Fs, "CERT008", low)),
    ?assert(has(Fs, "CERT007", low)).
expiring_soon_test() -> ?assert(has(run("expiring.pem", today()), "CERT001", high)).
expiring_medium_test() -> ?assert(has(run("expiring.pem", {2026, 11, 2}), "CERT001", medium)).
not_expiring_far_before_test() -> ?assertNot(has(run("expiring.pem", {2026, 10, 1}), "CERT001", high)).
expired_test() -> ?assert(has(run("expiring.pem", {2027, 3, 1}), "CERT001", critical)).
key_bits_test() ->
    {ok, B} = file:read_file("examples/certs/weak-rsa.pem"),
    [{'Certificate', Der, _}] = public_key:pem_decode(B),
    C = public_key:pkix_decode_cert(Der, otp),
    ?assertEqual({rsa, 1024}, certlint:key_bits(C)),
    ?assertEqual(365, certlint:validity_days(C)).
garbage_test() ->
    [{medium, "CERT000", "x", _}] = certlint:lint_pem(<<"not a cert">>, "x", today()).
truncated_pem_test() ->
    {ok, B} = file:read_file("examples/certs/good.pem"),
    Half = binary:part(B, 0, byte_size(B) div 2),
    [{medium, "CERT000", "x", _}] = certlint:lint_pem(Half, "x", today()).
bundle_test() ->
    {ok, A} = file:read_file("examples/certs/good.pem"),
    {ok, B} = file:read_file("examples/certs/weak-rsa.pem"),
    Fs = certlint:lint_pem(<<A/binary, B/binary>>, "bundle.pem", today()),
    ?assert(lists:any(fun({_, _, W, _}) -> lists:prefix("bundle.pem#2", W) end, Fs)).
directory_scan_test() ->
    {N, Fs} = certlint:lint_path("examples/certs", today()),
    ?assertEqual(6, N), ?assert(length(Fs) >= 10),
    [{S1, _, _, _} | _] = Fs, ?assertEqual(high, S1).
sorted_test() ->
    {_, Fs} = certlint:lint_path("examples/certs", today()),
    Ranks = [certlint:severity_rank(S) || {S, _, _, _} <- Fs],
    ?assertEqual(lists:sort(Ranks), Ranks).
tsv_test() ->
    Out = lists:flatten(certlint:render_tsv(certlint:lint_path("examples/certs", today()))),
    ?assert(lists:prefix("# 6 certificate files", Out)),
    ?assert(string:find(Out, "high\tCERT003\t") =/= nomatch).
text_test() ->
    Out = lists:flatten(certlint:render_text(certlint:lint_path("examples/certs", today()))),
    ?assert(string:find(Out, "HIGH") =/= nomatch).
cli_exit_codes_test() ->
    ?assertEqual(1, cmd("./bin/cert-lint examples/certs --today 2026-11-14 --fail-on high")),
    ?assertEqual(0, cmd("./bin/cert-lint examples/certs/good.pem --today 2026-11-14 --fail-on high")),
    ?assertEqual(2, cmd("./bin/cert-lint /no/such/path")),
    ?assertEqual(2, cmd("./bin/cert-lint examples/certs --today 2026-13-40")),
    ?assertEqual(2, cmd("./bin/cert-lint")).
cmd(C) ->
    P = open_port({spawn, "sh -c '" ++ C ++ " >/dev/null 2>&1; echo $?'"}, [exit_status, stream]),
    receive {P, {data, D}} -> flush(P), list_to_integer(string:trim(D)) after 15000 -> -1 end.
flush(P) -> receive {P, {exit_status, _}} -> ok after 2000 -> ok end.
