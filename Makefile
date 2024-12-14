# Makefile for PAM Example Module
CC = gcc
CFLAGS = -Wall -Wextra -fPIC -std=gnu99
LDFLAGS = -shared
PAM_LIB = -lpam

TARGET = pam_security_audit.so
SRC = pam.c

# 默认目标
all: $(TARGET)

# 生成目标
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(PAM_LIB)

# 清理生成的文件
clean:
	rm -f $(TARGET)

.PHONY: all clean
