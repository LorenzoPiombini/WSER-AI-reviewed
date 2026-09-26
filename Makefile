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

.PHONY: default clean library db install test
default: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) $(SANITIZERS) -o $@ $^ $(LDLIBS)

obj/%.o: src/%.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SANITIZERS) -MMD -MP -c $< -o $@

obj/db/%.o: src/%.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) -DOWN_DB $(CFLAGS) $(SANITIZERS) -MMD -MP -c $< -o $@

db: $(DBOBJ)
	$(CC) $(LDFLAGS) $(SANITIZERS) -o $@ $^ $(LDLIBS) -lcrud -ldblua -llua5.4 -lworker

library: $(SHAREDLIBnet)
$(SHAREDLIBnet): $(OBJlibnet)
	$(CC) $(LDFLAGS) $(SANITIZERS) -shared -o $@ $^ $(LDLIBS)

obj/regression: tests/regression.c obj/json.o $(OBJlibnet)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SANITIZERS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

obj/json-tests: json_parser_test.c obj/json.o
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SANITIZERS) $(LDFLAGS) -o $@ $^

obj/tls-tests: tests/tls.c $(OBJlibnet)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SANITIZERS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

obj/infrastructure-tests: tests/infrastructure.c obj/load.o $(OBJlibnet)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SANITIZERS) $(LDFLAGS) -Wl,--wrap=getuid,--wrap=socket,--wrap=bind,--wrap=listen,--wrap=connect,--wrap=accept4,--wrap=read -o $@ $^ $(LDLIBS)

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
