DIR_INC = ./include
DIR_SRC = ./src
DIR_OBJ = ./obj
DIR_BIN = ./bin

SRC = $(wildcard ${DIR_SRC}/*.cpp)  
OBJ = $(patsubst %.cpp, ${DIR_OBJ}/%.o, $(notdir ${SRC})) 

TARGET = chat
BIN_TARGET = ${DIR_BIN}/${TARGET}

CC = g++
CFLAGS = -g -O3 -Wall -I${DIR_INC} -lpthread -std=c++11

${BIN_TARGET}:${OBJ}
	$(CC) $(OBJ) -o $@ $(CFLAGS)

${DIR_OBJ}/%.o:${DIR_SRC}/%.cpp
	$(CC) -c $< -o $@ $(CFLAGS)

.PHONY:clean test
clean:
	find ${DIR_OBJ} -name *.o -exec rm -rf {} \;
	find ${DIR_BIN} -type f -exec rm -rf {} \;

# CRSASection测试部分
test:${DIR_BIN}/CRsa
	${DIR_BIN}/CRsa

${DIR_BIN}/CRsa:${DIR_SRC}/CRSASection.cpp
	$(CC) $< -o $@ -std=c++11 -I${DIR_INC} -DTEST
