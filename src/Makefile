# CS 6238 Project 1
# Andrew Wilder
# Prabhendu Pandey

CC  = javac
SRC = $(wildcard *.java)
OBJ = $(SRC:%.java=%.class)

%.class : %.java
	@echo "[CC] $<"
	@$(CC) $<

all : $(OBJ)
	@echo "Compilation complete."
	@echo "Usage: java SecLogin [testfile.txt]"

clean :
	@echo "Removing compiled class files"
	@rm -rf *.class
