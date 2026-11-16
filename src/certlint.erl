%% cert-lint: offline X.509 certificate linter. Erlang/OTP, uses the public_key application.
-module(certlint).
-include_lib("public_key/include/public_key.hrl").
-export([lint_pem/3, lint_path/2, parse_date/1, render_text/1, render_tsv/1, severity_rank/1, key_bits/1, validity_days/1]).

%% finding: {Severity, Rule, Where, Message}

severity_rank(critical) -> 0;
severity_rank(high) -> 1;
severity_rank(medium) -> 2;
severity_rank(low) -> 3.

%% "YYYY-MM-DD" -> {Y,M,D}
parse_date(S) ->
    [Y, M, D] = [list_to_integer(P) || P <- string:split(S, "-", all)],
    true = calendar:valid_date(Y, M, D),
    {Y, M, D}.

%% ASN.1 time -> {Y,M,D}
asn_date({utcTime, [Y1, Y2, M1, M2, D1, D2 | _]}) ->
    YY = list_to_integer([Y1, Y2]),
    Y = if YY >= 50 -> 1900 + YY; true -> 2000 + YY end,
    {Y, list_to_integer([M1, M2]), list_to_integer([D1, D2])};
asn_date({generalTime, [Y1, Y2, Y3, Y4, M1, M2, D1, D2 | _]}) ->
    {list_to_integer([Y1, Y2, Y3, Y4]), list_to_integer([M1, M2]), list_to_integer([D1, D2])}.

days(D) -> calendar:date_to_gregorian_days(D).

validity_days(#'OTPCertificate'{tbsCertificate = T}) ->
    #'Validity'{notBefore = B, notAfter = A} = T#'OTPTBSCertificate'.validity,
    days(asn_date(A)) - days(asn_date(B)).

name_of({rdnSequence, Rdns}) ->
    Vals = [value_str(V) || Rdn <- Rdns, #'AttributeTypeAndValue'{type = ?'id-at-commonName', value = V} <- Rdn],
    case Vals of [CN | _] -> CN; [] -> "(no CN)" end;
name_of(_) -> "(unknown)".

value_str({_, V}) when is_binary(V) -> binary_to_list(V);
value_str({_, V}) when is_list(V) -> V;
value_str(V) when is_binary(V) -> binary_to_list(V);
value_str(V) when is_list(V) -> V;
value_str(_) -> "?".

key_bits(#'OTPCertificate'{tbsCertificate = T}) ->
    #'OTPSubjectPublicKeyInfo'{subjectPublicKey = K} = T#'OTPTBSCertificate'.subjectPublicKeyInfo,
    case K of
        #'RSAPublicKey'{modulus = N} -> {rsa, bit_length(N)};
        {#'ECPoint'{}, _} -> {ec, 0};
        #'ECPoint'{} -> {ec, 0};
        _ -> {other, 0}
    end.

bit_length(N) when N > 0 -> length(integer_to_list(N, 2)).

sig_oid(#'OTPCertificate'{signatureAlgorithm = #'SignatureAlgorithm'{algorithm = Oid}}) -> Oid.

san(#'OTPCertificate'{tbsCertificate = T}) ->
    Exts = case T#'OTPTBSCertificate'.extensions of asn1_NOVALUE -> []; L -> L end,
    lists:append([ [value_str(V) || {dNSName, V} <- Vals]
                 || #'Extension'{extnID = ?'id-ce-subjectAltName', extnValue = Vals} <- Exts, is_list(Vals) ]).

-define(SHA1_RSA, {1,2,840,113549,1,1,5}).
-define(MD5_RSA, {1,2,840,113549,1,1,4}).
-define(SHA1_ECDSA, {1,2,840,10045,4,1}).

lint_cert(Cert = #'OTPCertificate'{tbsCertificate = T}, Today, Where0) ->
    CN = name_of(T#'OTPTBSCertificate'.subject),
    Where = Where0 ++ " (" ++ CN ++ ")",
    #'Validity'{notAfter = After} = T#'OTPTBSCertificate'.validity,
    Left = days(asn_date(After)) - days(Today),
    IsCa = lists:any(fun(#'Extension'{extnID = ?'id-ce-basicConstraints', extnValue = #'BasicConstraints'{cA = true}}) -> true; (_) -> false end,
                     case T#'OTPTBSCertificate'.extensions of asn1_NOVALUE -> []; L -> L end),
    Selfsigned = T#'OTPTBSCertificate'.issuer =:= T#'OTPTBSCertificate'.subject,
    Expiry =
        if Left < 0 -> [{critical, "CERT001", Where, "expired " ++ integer_to_list(-Left) ++ " days ago"}];
           Left =< 14 -> [{high, "CERT001", Where, "expires in " ++ integer_to_list(Left) ++ " days"}];
           Left =< 30 -> [{medium, "CERT001", Where, "expires in " ++ integer_to_list(Left) ++ " days"}];
           true -> []
        end,
    Key = case key_bits(Cert) of
              {rsa, B} when B < 1024 -> [{critical, "CERT002", Where, "RSA key of " ++ integer_to_list(B) ++ " bits can be factored"}];
              {rsa, B} when B < 2048 -> [{high, "CERT002", Where, "RSA key of " ++ integer_to_list(B) ++ " bits is below the 2048-bit minimum"}];
              _ -> []
          end,
    Quantum = case key_bits(Cert) of
                  {rsa, B2} -> [{low, "CERT007", Where, "RSA-" ++ integer_to_list(B2) ++ " is not quantum-safe: plan the migration"}];
                  {ec, _} -> [{low, "CERT007", Where, "elliptic-curve key is not quantum-safe: plan the migration"}];
                  _ -> []
              end,
    %% A self-signed root is a trust anchor: clients never verify its own signature, so an old hash there is not exploitable.
    RootNote = Selfsigned andalso IsCa,
    Sig = case sig_oid(Cert) of
              ?SHA1_RSA when RootNote -> [{low, "CERT003", Where, "self-signed root signed with SHA-1: not validated by clients, but check that nothing is issued with SHA-1 below it"}];
              ?SHA1_ECDSA when RootNote -> [{low, "CERT003", Where, "self-signed root signed with SHA-1: not validated by clients, but check that nothing is issued with SHA-1 below it"}];
              ?MD5_RSA when RootNote -> [{low, "CERT003", Where, "self-signed root signed with MD5: not validated by clients, but check that nothing is issued with MD5 below it"}];
              ?SHA1_RSA -> [{high, "CERT003", Where, "signed with SHA-1"}];
              ?SHA1_ECDSA -> [{high, "CERT003", Where, "signed with SHA-1"}];
              ?MD5_RSA -> [{high, "CERT003", Where, "signed with MD5"}];
              _ -> []
          end,
    Sans = san(Cert),
    NoSan = case {Sans, IsCa} of {[], false} -> [{high, "CERT005", Where, "no Subject Alternative Name: modern clients ignore the CN"}]; _ -> [] end,
    Long = case {validity_days(Cert) > 398, IsCa, Selfsigned} of
               {true, false, _} -> [{medium, "CERT004", Where, "valid for " ++ integer_to_list(validity_days(Cert)) ++ " days: above the 398-day limit for public certificates"}];
               _ -> []
           end,
    Wild = case lists:any(fun(S) -> lists:prefix("*.", S) end, [CN | Sans]) of
               true -> [{low, "CERT008", Where, "wildcard certificate: one stolen key exposes every subdomain"}];
               false -> []
           end,
    Expiry ++ Key ++ Sig ++ NoSan ++ Long ++ Wild ++ Quantum.

%% lint_pem(Binary, Name, Today) -> [finding]
lint_pem(Bin, Name, Today) ->
    Entries = try public_key:pem_decode(Bin) catch _:_ -> [] end,
    Certs = [E || {'Certificate', _, not_encrypted} = E <- Entries],
    case Certs of
        [] -> [{medium, "CERT000", Name, "no certificate found in this file"}];
        _ ->
            lists:append([ try
                               Cert = public_key:pkix_decode_cert(Der, otp),
                               W = case length(Certs) of 1 -> Name; _ -> Name ++ "#" ++ integer_to_list(I) end,
                               lint_cert(Cert, Today, W)
                           catch _:_ -> [{medium, "CERT000", Name, "certificate could not be decoded"}] end
                           || {I, {'Certificate', Der, _}} <- lists:zip(lists:seq(1, length(Certs)), Certs) ])
    end.

files(Path) ->
    case filelib:is_dir(Path) of
        true -> lists:sort([F || F <- filelib:wildcard(filename:join(Path, "**")), filelib:is_regular(F), lists:member(filename:extension(F), [".pem", ".crt", ".cer"])]);
        false -> [Path]
    end.

lint_path(Path, Today) ->
    Fs = files(Path),
    Rel = fun(F) -> case filelib:is_dir(Path) of true -> string:slice(F, length(Path) + 1); false -> filename:basename(F) end end,
    All = lists:append([ case file:read_file(F) of
                             {ok, B} -> lint_pem(B, Rel(F), Today);
                             {error, R} -> [{medium, "CERT000", Rel(F), "cannot read: " ++ atom_to_list(R)}]
                         end || F <- Fs ]),
    {length(Fs), lists:sort(fun({S1, R1, W1, _}, {S2, R2, W2, _}) -> {severity_rank(S1), W1, R1} =< {severity_rank(S2), W2, R2} end, All)}.

render_text({N, Fs}) ->
    [io_lib:format("~p files, ~p findings~n", [N, length(Fs)])
     | [io_lib:format("~-9s ~s ~s~n          ~s~n", [string:uppercase(atom_to_list(S)), R, W, M]) || {S, R, W, M} <- Fs]].

render_tsv({N, Fs}) ->
    [io_lib:format("# ~p certificate files, ~p findings~n", [N, length(Fs)])
     | [io_lib:format("~s\t~s\t~s\t~s~n", [S, R, W, M]) || {S, R, W, M} <- Fs]].
