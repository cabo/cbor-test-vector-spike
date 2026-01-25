test-vector-spike.csv: test-vector-spike.rb Makefile
	ruby $< -s 47110815 > $@
	wc -cl $@
