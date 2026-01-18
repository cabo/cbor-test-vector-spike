test-vector-spike.csv: test-vector-spike.rb Makefile
	ruby $< > $@
	wc -l $@
