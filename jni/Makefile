INSTALL_PATH= /usr/local
CODER_INCLUDE= $(INSTALL_PATH)/include/coder

LD= g++
LDPATHS=
LDLIBS=
LDFLAGS= -Wall -g -shared -Wl,--no-undefined -Wl,--add-stdcall-alias $(LDPATHS) $(LDLIBS)

CPP= g++
CPPDEFINES= -D_GNU_SOURCE -D_REENTRANT
CPPINCLUDES=
CPPFLAGS= -Wall -g -std=c++11 -MMD -fPIC $(CPPDEFINES) $(CPPINCLUDES)

CPP_SOURCES= BigInteger.cc
CPP_OBJECT= $(CPP_SOURCES:.cc=.o)
DEPEND= $(CPP_OBJECT:.o=.d)

.PHONY: clean install

JNI_HEADERS= org_cryptokitty_jni_BigInteger.h
BUILD_DIR= build

LIBRARY= libckjni.so

all: $(LIBRARY)

$(CPP_OBJECT): %.o: %.cc
	$(CPP) -c $(CPPFLAGS) -o $@ $<

$(LIBRARY): $(CPP_OBJECT)
	$(LD) -o $@ $(CPP_OBJECT) $(LDFLAGS)

clean:
	-rm -rf $(CPP_OBJECT) $(DEPEND) $(LIBRARY) $(JNI_HEADERS) $(BUILD_DIR)

install:
	rm -rf $(CODER_INCLUDE)
	mkdir -p $(CODER_INCLUDE)
	cp --preserve=timestamps *.h $(CODER_INCLUDE)
	chmod 755 $(CODER_INCLUDE)
	chmod 644 $(CODER_INCLUDE)/*
	chown -R root:root $(CODER_INCLUDE)
	cp --preserve=timestamps $(LIBRARY) $(INSTALL_PATH)/lib64
	chmod 755 $(INSTALL_PATH)/lib64/$(LIBRARY)
	chown root:root $(INSTALL_PATH)/lib64/$(LIBRARY)
	strip $(INSTALL_PATH)/lib64/$(LIBRARY)

-include $(DEPEND)
