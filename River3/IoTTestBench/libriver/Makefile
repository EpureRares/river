CC=gcc
CCFLAGS=-Wall

BIN=bin
OBJ=obj
SRC=src

SOURCES := $(wildcard $(SRC)/*.c)
OBJECTS := $(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SOURCES))

CLIENT_SRCS := $(wildcard $(SRC)/process-wrapper*.c)
CLIENT_OBJECTS := $(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(CLIENT_SRCS))

SERVER_SRCS := $(wildcard $(SRC)/server*.c)
SERVER_OBJECTS := $(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SERVER_SRCS))

LIB_SRCS := $(wildcard $(SRC)/libriver*.c)
LIB_OBJECTS := $(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(LIB_SRCS))
LIB_NAME=libriver.so

# Check if patchelf is installed
PATCHELF_EXISTS=$(shell patchelf --version 2> /dev/null)

all: $(BIN)/process-wrapper $(BIN)/server $(BIN)/$(LIB_NAME)

$(BIN)/process-wrapper: $(CLIENT_OBJECTS) $(BIN)/$(LIB_NAME)
	@test -d $(BIN) || mkdir -p $(BIN)
	@#$(CC) $(CCFLAGS) $(LFLAGS) $(CLIENT_OBJECTS) -lriver -L$(BIN) -Wl,-rpath=$(BIN) -o $@
	$(CC) $(CCFLAGS) $(LFLAGS) $(CLIENT_OBJECTS) -o $@
ifneq (, $(PATCHELF_EXISTS))
	$(info Patch process with custom library if patchelf is installed)
	$(info Otherwise, LD_PRELOAD should be used to preload $(LIB_NAME))
	patchelf --add-needed `pwd`/$(BIN)/$(LIB_NAME) $@
endif

$(BIN)/server: $(SERVER_OBJECTS)
	@test -d $(BIN) || mkdir -p $(BIN)
	$(CC) $(CCFLAGS) $(LFLAGS) $^ -o $@

$(BIN)/$(LIB_NAME): $(LIB_OBJECTS)
	@test -d $(BIN) || mkdir -p $(BIN)
	$(CC) $(CCFLAGS) $(LFLAGS) -shared -Wl,-z,now $^ -o $@

$(OBJ)/libriver.o: $(LIB_SRCS)
	@test -d $(OBJ) || mkdir -p $(OBJ)
	$(CC) $(CCFLAGS) $(LFLAGS) -fPIC -c $< -o $@

$(OBJ)/%.o: $(SRC)/%.c
	@test -d $(OBJ) || mkdir -p $(OBJ)
	$(CC) $(CCFLAGS) $(LFLAGS) -c $< -o $@
run:
	$(BIN)/process-wrapper

clean:
	rm -rf $(OBJ) $(BIN)

.PHONY: clean
