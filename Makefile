test-vector-spike.csv: test-vector-spike.rb Makefile
	ruby $< -s 47110815 > $@
	wc -cl $@

test-vector-diag.csv: test-vector-spike.rb Makefile
	ruby $< -ds 47110815 > $@
	wc -cl $@

test-vector-diag-pretty.csv: test-vector-spike.rb Makefile
	ruby $< -pds 47110815 > $@
	wc -cl $@

all: test-vector-diag-pretty.csv test-vector-diag.csv test-vector-spike.csv
