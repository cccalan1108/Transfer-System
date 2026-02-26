# 編譯器設定
CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17

# OpenSSL 和其他函式庫
LIBS_CLIENT = -lssl -lcrypto
LIBS_SERVER = -lssl -lcrypto -pthread

# 目標檔案
CLIENT_TARGET = client
SERVER_TARGET = server

# 來源檔案
CLIENT_SRCS = client.cpp
SERVER_SRCS = server.cpp

# 預設目標
all: $(CLIENT_TARGET) $(SERVER_TARGET)

# 編譯 client
$(CLIENT_TARGET): $(CLIENT_SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS_CLIENT)

# 編譯 server
$(SERVER_TARGET): $(SERVER_SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS_SERVER)

# 清除生成的檔案
clean:
	rm -f $(CLIENT_TARGET) $(SERVER_TARGET)

# PHONY 目標
.PHONY: all clean
