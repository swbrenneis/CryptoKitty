INSTALL_PATH= /usr/local

LD= g++
LDPATHS= -L/usr/local/lib64
LDLIBS= -lcryptokitty -lcoder -lpthread
LDFLAGS= -Wall -g -shared -Wl,--no-undefined $(LDPATHS) $(LDLIBS)

CPP= g++
CPPDEFINES= -D_GNU_SOURCE -D_REENTRANT
CPPINCLUDES= -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux \
			 -I/usr/local/include/CryptoKitty-C
CPPFLAGS= -Wall -g -std=c++11 -Wl,--add-stdcall-alias -MMD -fPIC $(CPPDEFINES) $(CPPINCLUDES)

CPP_SOURCES= ByteArrayCodec.cc ReferenceManager.cc SocketImpl.cc StringHandler.cc aes.cc \
			 berkeleysocketimpl.cc biginteger.cc fortunarandom.cc gcm.cc hmac.cc \
			 rsakeypairgenerator.cc

CPP_OBJECT= $(CPP_SOURCES:.cc=.o)
DEPEND= $(CPP_OBJECT:.o=.d)

.PHONY: clean install

JNI_HEADERS= org_cryptokitty_jni_BigInteger.h org_cryptokitty_random_FortunaSecureRandom.h \
			 org_cryptokitty_cipher_AES.h org_cryptokitty_modes_GCM.h org_cryptokitty_mac_HMAC.h \
			 org_cryptokitty_keys_RSAKeyPairGenerator.h org_cryptokitty_jni_JNIReference.h \
			 org_cryptokitty_jni_BerkeleySocketImpl.h

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
	cp --preserve=timestamps $(LIBRARY) $(INSTALL_PATH)/lib64
	chmod 755 $(INSTALL_PATH)/lib64/$(LIBRARY)
	chown root:root $(INSTALL_PATH)/lib64/$(LIBRARY)
#	strip $(INSTALL_PATH)/lib64/$(LIBRARY)

-include $(DEPEND)
