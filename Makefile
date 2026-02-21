test-vector-spike.edn0: test-vector-csv.rb test-vector-spike.csv Makefile
	ruby $< test-vector-spike.csv -t edn > $@

test-vector-spike.edn: test-vector-csv.rb test-vector-spike.csv Makefile
	ruby $< test-vector-spike.csv -w 200 -t edn > $@

test-vector-spike.cbor: test-vector-csv.rb test-vector-spike.csv Makefile
	ruby $< test-vector-spike.csv -t cbor > $@

test-vector-spike.json: test-vector-csv.rb test-vector-spike.csv Makefile
	ruby $< test-vector-spike.csv -t json > $@

test-vector-spike.csv: test-vector-spike.rb Makefile
	ruby $< -s 47110815 > $@
	ruby test-vector-csv.rb -tcheck $@
	wc -cl $@

test-vector-diag.csv: test-vector-spike.rb Makefile
	ruby $< -ds 47110815 > $@
	wc -cl $@

test-vector-diag-pretty.csv: test-vector-spike.rb Makefile
	ruby $< -pds 47110815 > $@
	wc -cl $@

all: test-vector-diag-pretty.csv test-vector-diag.csv test-vector-spike.csv test-vector-spike.edn test-vector-spike.edn0 test-vector-spike.cbor test-vector-spike.json
