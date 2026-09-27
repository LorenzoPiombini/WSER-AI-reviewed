.DEFAULT_GOAL := default
CC ?= gcc
CPPFLAGS += -Iinclude
CFLAGS ?= -Wall -Wextra -g3 -fstack-protector-strong -fPIC
LDFLAGS ?= -Wl,-z,relro,-z,now,-z,noexecstack
LDLIBS = -lcrypto -lssl
SANITIZERS ?= -fsanitize=address,undefined
TARGET = wser
SRC = $(wildcard src/*.c)
OBJ = $(patsubst src/%.c,obj/%.o,$(SRC))
DBOBJ = $(patsubst src/%.c,obj/db/%.o,$(SRC))
OBJlibnet = obj/network.o obj/request.o obj/response.o obj/monitor.o
LIBDIR ?= /usr/local/lib
INCLUDEDIR ?= /usr/local/include
SHAREDLIBnet = libnet.so

# Detect if the OS is Fedora
IS_FEDORA := $(shell grep -E '^ID="?fedora"?' /etc/os-release > /dev/null 2>&1 && echo yes || echo no)

.PHONY: default clean library db install test
default: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) $(SANITIZERS) -o $@ $^ $(LDLIBS)

obj/%.o: src/%.c
	@mkdir -p $(@D)
	if [ "$(IS_FEDORA)" = "no" ]; then \
		$(CC) $(CPPFLAGS) $(CFLAGS) $(SANITIZERS) -MMD -MP -c $< -o $@;\
	else\
		$(CC) $(CPPFLAGS) $(CFLAGS) -DFEDORA $(SANITIZERS) -MMD -MP -c $< -o $@;\
	fi

obj/db/%.o: src/%.c
	@mkdir -p $(@D)
	if [ "$(IS_FEDORA)" = "no" ]; then \
		$(CC) $(CPPFLAGS) -DOWN_DB $(CFLAGS) $(SANITIZERS) -MMD -MP -c $< -o $@;\
	else \
		$(CC) $(CPPFLAGS) -DFEDORA -DOWN_DB $(CFLAGS) $(SANITIZERS) -MMD -MP -c $< -o $@;\
	fi

db: $(DBOBJ)
	if [ "$(IS_FEDORA)" = "no" ]; then \
		$(CC) $(LDFLAGS) $(SANITIZERS) -o $@ $^ $(LDLIBS) -lcrud -llua -lworker;\
	else \
		$(CC) $(LDFLAGS) $(SANITIZERS) -DFEDORA -o $@ $^ $(LDLIBS) -lcrud -llua -lworker;\
	fi


library: $(SHAREDLIBnet)
$(SHAREDLIBnet): $(OBJlibnet)
	if [ "$(IS_FEDORA)" = "no" ]; then \
		$(CC) $(LDFLAGS) $(SANITIZERS) -shared -o $@ $^ $(LDLIBS);\
	else\
		$(CC) $(LDFLAGS) $(SANITIZERS) -DFEDORA -shared -o $@ $^ $(LDLIBS);\
	fi

obj/regression: tests/regression.c obj/json.o $(OBJlibnet)
	if [ "$(IS_FEDORA)" = "no" ]; then \
		$(CC) $(CPPFLAGS) $(CFLAGS) $(SANITIZERS) $(LDFLAGS) -o $@ $^ $(LDLIBS);\
	else\
		$(CC) $(CPPFLAGS) $(CFLAGS) $(SANITIZERS) $(LDFLAGS) -DFEDORA -o $@ $^ $(LDLIBS);\
	fi

obj/json-tests: json_parser_test.c obj/json.o
	if [ "$(IS_FEDORA)" = "no" ]; then \
		$(CC) $(CPPFLAGS) $(CFLAGS) $(SANITIZERS) $(LDFLAGS) -o $@ $^;\
	else\
		$(CC) $(CPPFLAGS) $(CFLAGS) $(SANITIZERS) $(LDFLAGS) -DFEDORA -o $@ $^; \
	fi

obj/tls-tests: tests/tls.c $(OBJlibnet)
	if [ "$(IS_FEDORA)" = "no" ]; then \
		$(CC) $(CPPFLAGS) $(CFLAGS) $(SANITIZERS) $(LDFLAGS) -o $@ $^ $(LDLIBS);\
	else\
		$(CC) $(CPPFLAGS) $(CFLAGS) $(SANITIZERS) $(LDFLAGS) -DFEDORA -o $@ $^ $(LDLIBS);\
	fi

obj/infrastructure-tests: tests/infrastructure.c obj/load.o $(OBJlibnet)
	if [ "$(IS_FEDORA)" = "no" ]; then \
		$(CC) $(CPPFLAGS) $(CFLAGS) $(SANITIZERS) $(LDFLAGS) -Wl,--wrap=getuid,--wrap=socket,--wrap=bind,--wrap=listen,--wrap=connect,--wrap=accept4,--wrap=read -o $@ $^ $(LDLIBS)
	else\
		$(CC) $(CPPFLAGS) $(CFLAGS) $(SANITIZERS) $(LDFLAGS) -DFEDORA -Wl,--wrap=getuid,--wrap=socket,--wrap=bind,--wrap=listen,--wrap=connect,--wrap=accept4,--wrap=read -o $@ $^ $(LDLIBS)\
	fi

obj/test-cert.pem:
	@mkdir -p obj
	openssl req -x509 -newkey rsa:2048 -nodes -keyout obj/test-key.pem -out $@ -subj /CN=localhost -days 1 2>/dev/null

test: obj/regression obj/json-tests obj/tls-tests obj/test-cert.pem obj/infrastructure-tests
	./obj/infrastructure-tests
	./obj/regression
	./obj/json-tests
	./obj/tls-tests obj/test-cert.pem obj/test-key.pem

clean:
	rm -rf obj
	rm -f $(TARGET) db $(SHAREDLIBnet)

install: $(TARGET) library
	install -d $(INCLUDEDIR) $(LIBDIR)
	install -m 644 include/load.h include/network.h include/request.h include/response.h $(INCLUDEDIR)/
	install -m 755 $(SHAREDLIBnet) $(LIBDIR)
	ldconfig

-include $(OBJ:.o=.d) $(DBOBJ:.o=.d)
