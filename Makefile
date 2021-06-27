CC=gcc
CFLAGS=-g -Wall -Werror `curl-config --cflags` 
LDLIBS=`curl-config --libs` -lzmq -lpthread -lhiredis
BUILD_DIR=build
EXEC_DIR=build/bin
SRC_DIR=src
EXE_LIST=${SRC_DIR}/worker
OBJ=${SRC_DIR}/cJSON.o ${SRC_DIR}/bot.o
NODE_NAME := $(shell uname -n)

#${SRC_DIR}/list.o

all: create_dirs ${OBJ} ${EXE_LIST}

create_dirs: ; @mkdir -p ${BUILD_DIR} ${EXEC_DIR}

${EXE_LIST}: ${SRC_DIR}/worker.c
	${CC} ${OBJ} $< ${CFLAGS} ${LDLIBS} -o $@ 
	mv $@ ${EXEC_DIR}

.PHONY: run
run: ; ${EXEC_DIR}/worker &
	${EXEC_DIR}/bot

.PHONY: clean
clean:
	@rm -rf ${BUILD_DIR}

