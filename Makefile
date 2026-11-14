build:
	mkdir -p ebin && erlc -o ebin src/*.erl

test:
	mkdir -p ebin && erlc -o ebin src/*.erl tests/*.erl && erl -noshell -pa ebin -eval 'case eunit:test(certlint_tests) of ok -> halt(0); _ -> halt(1) end.'

sample: build
	./bin/cert-lint examples/certs --today 2026-11-14 > docs/sample-output.txt; true
	./bin/cert-lint examples/certs --today 2026-11-14 --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "cert-lint" "Offline X.509 certificate linter: expiry, weak keys, SHA-1, missing SAN, quantum exposure. Erlang/OTP." "Synthetic certificates for example.test hosts, evaluated at 2026-11-14."
