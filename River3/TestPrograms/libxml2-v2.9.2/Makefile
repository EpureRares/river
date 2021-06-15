OUT=out
CXX=clang++

.PHONY: clean

$(OUT)/xml: target.cc river_shim.o libxml2/.libs/libxml2.a
	test -d $(OUT) || mkdir -p $(OUT)
	#$(CXX) $(CXXFLAGS) -std=c++11 target.cc -I libxml2/include libxml2/.libs/libxml2.a river_shim.o -o $(OUT)/xml
	$(CXX) $(CXXFLAGS) -std=c++11 -g -O0 target.cc -I libxml2/include libxml2/.libs/libxml2.a river_shim.o -o $(OUT)/xml
	#$(CXX) $(CXXFLAGS) -std=c++11 -g -O0 target.cc -I libxml2/include libxml2/.libs/libxml2.a river_shim.o -static -o $(OUT)/xml

libxml2/.libs/libxml2.a:
	test -d libxml2 || git clone https://gitlab.gnome.org/GNOME/libxml2.git
	test -d libxml2 && cd libxml2 \
		&& git checkout -f v2.9.2 \
		&& ./autogen.sh \
		&& CCLD="$(CXX) $(CXXFLAGS)" ./configure --without-python --with-threads=no --with-zlib=no --with-lzma=no \
		&& make -j $(nproc)

river_shim.o: river_shim.cpp
	#$(CXX) $(CXXFLAGS) -stdlib=libc++ -std=c++11 -O2 -c river_shim.cpp -o river_shim.o
	#$(CXX) $(CXXFLAGS) -std=c++11 -O2 -c river_shim.cpp -o river_shim.o
	$(CXX) $(CXXFLAGS) -std=c++11 -O0 -g -c river_shim.cpp -o river_shim.o

$(OUT)/fuxx-target.dict:
	wget -qO $OUT/fuzz-target.dict https://raw.githubusercontent.com/google/AFL/debe27037b9444bbf090a0ffbd5d24889bb887ae/dictionaries/xml.dict

dump: $(OUT)/xml
	objdump -D -M intel $(OUT)/xml > dump.asm

clean:
	rm $(OUT)/xml river_shim.o
