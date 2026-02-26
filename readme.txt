Step0.安裝openssl


Step1.編譯指令:

  g++ server.cpp -o server -lssl -lcrypto -pthread
  g++ client.cpp -o client -lssl -lcrypto

Step2.執行指令:

  ./server
  ./client
