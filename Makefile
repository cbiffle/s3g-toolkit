CXX=g++

all: s3g-reencap

clean:
	-rm -f s3g-reencap

s3g-reencap: s3g-reencap.cc
	$(CXX) -o $@ $^
