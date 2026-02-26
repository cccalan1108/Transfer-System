#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h> //gain access to the definition of _LP64 and _ILP32
#include <sys/socket.h> //makes available a type, socklen_t
#include <netinet/in.h> //defines the IN6ADDR_LOOPBACK_INIT macro
#include <arpa/inet.h> //inet_addr()
#include <string>
#include <unistd.h>
#include <cstring>
#include <exception>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <algorithm>  // 为了使用 transform
using namespace std;

#define MAX_STRING_LENGTH 500
#define LISTEN_BACKLOG 10

// ssl
SSL_CTX* InitClientCTX();//Use SSLv23_client_method() to initialize SSL Content Text
SSL_CTX* InitServerCTX();//Use SSLv23_server_method() to initialize SSL Content Text
void LoadCertificates(SSL_CTX* ctx);//load user's certificate & load user's private key & check correctness of private key
void ShowCerts(SSL *ssl);

SSL_CTX* InitClientCTX()
{
    SSL_CTX *ctx;
    // Initialize SSL
    SSL_library_init();
    // load all SSL Algorithms
    OpenSSL_add_all_algorithms();
    // load all SSL error messages
    SSL_load_error_strings();
    // Use SSL V2 & V3 standard to generate SSL_CTX, which is SSL Content Text 
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stdout);
        abort();
    }
    return ctx;
}


SSL_CTX* InitServerCTX()
{
    SSL_CTX *ctx;
    // Initialize SSL
    SSL_library_init();
    // load all SSL Algorithms
    OpenSSL_add_all_algorithms();
    // load all SSL error messages
    SSL_load_error_strings();
    // Use SSL V2 & V3 standard to generate SSL_CTX, which is SSL Content Text 
    ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stdout);
        abort();
    }
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx)
{
    //Auto generate certificate
    EVP_PKEY * pkey;
    pkey = EVP_PKEY_new();
    RSA * rsa;
    rsa = RSA_generate_key(
        2048,   /* number of bits for the key - 2048 is a sensible value */
        RSA_F4, /* exponent - RSA_F4 is defined as 0x10001L */
        NULL,   /* callback - can be NULL if we aren't displaying progress */
        NULL    /* callback argument - not needed in this case */
    );
    EVP_PKEY_assign_RSA(pkey, rsa);

    X509 * x509;
    x509 = X509_new();

    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    X509_set_pubkey(x509, pkey);

    X509_NAME * name;
    name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"TW", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"USER", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"127.0.0.1", -1, -1, 0);
    X509_set_issuer_name(x509, name);
    X509_sign(x509, pkey, EVP_sha1());
    //End Auto generate certificate

    // load client's digital certificate. The certificate is used to sending to client. The certificate include public key
    if ( SSL_CTX_use_certificate(ctx, x509) <= 0 ) 
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // load user's private key
    if ( SSL_CTX_use_PrivateKey(ctx, pkey) <= 0 ) 
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    //Check the correctness of client's private key
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void ShowCerts(SSL *ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL)
    {
        printf("Digital certificate information:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Certificate: %s\n", line);

        free(line);

        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);

        free(line);
        X509_free(cert);
    }
    else
        printf("No certificate information！\n");
}


// client class
class Client{
private:
    string IP;
    SSL* clientSSL;
public:
    Client();
    Client(string, int, SSL*);
    int sockfd;
    string getIP();
    SSL* getSSL();
};

Client::Client(){
    this->IP = "";
    this->sockfd = 0;
    this->clientSSL = nullptr;
}

Client::Client(string IP, int sockfd, SSL* clientSSL){
    this->IP = IP;
    this->sockfd = sockfd;
    this->clientSSL = clientSSL;
}

string Client::getIP(){
    return this->IP;
}

SSL* Client::getSSL(){
    return this->clientSSL;
}



int main(){

    SSL_CTX* ctx = InitClientCTX();
    LoadCertificates(ctx);

    //create socket
    int socket_d = 0;
    socket_d = socket(AF_INET, SOCK_STREAM, 0);

    if (socket_d == -1){
        cout << "Fail to create a socket" << endl;
    }

    int hostPort = 0;
    string hostIP;
    cout << "Wellcome! Please enter server's port number: ";
    cin >> hostPort;
    cin.ignore(MAX_STRING_LENGTH,'\n');
    cout << "Please enter the IP address(or enter 'localhost' instead): ";
    cin >> hostIP;
    cin.ignore(MAX_STRING_LENGTH,'\n');

    if(hostIP.compare("localhost")==0){
        hostIP = "127.0.0.1";
    }

    //Setting socket information
    struct sockaddr_in sockInfo;
    sockInfo.sin_family = AF_INET;//IPv4
    sockInfo.sin_addr.s_addr = inet_addr(hostIP.c_str());
    sockInfo.sin_port = htons(hostPort);

    //establish a connection
    int isConnect = connect(socket_d, (struct sockaddr*)&sockInfo, sizeof(sockInfo));
    SSL* ssl;
    if(isConnect == -1){
        cout << "Fail to connect." << endl;
        exit(EXIT_FAILURE);
        close(socket_d);
    }
    else{
        // generate a new SSL based on ctx
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, socket_d);

        //establish SSL connection
        if (SSL_connect(ssl) == -1){
            ERR_print_errors_fp(stderr);
        }
        else{
            printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
            ShowCerts(ssl);
        }  
    }

    char recvMessage[MAX_STRING_LENGTH];
    SSL_read(ssl, &recvMessage, sizeof(recvMessage));
    cout << recvMessage << endl;

    memset(recvMessage, '\0', sizeof(recvMessage));
    SSL_read(ssl, &recvMessage, sizeof(recvMessage));
    cout << recvMessage << endl;

    string sendMessage;
    //main function
    while(true){
        //function list
        string choice;
        cout << "\n======================\n\nChoose a function:" << endl;
        cout << "Please enter '1' or 'register' for registration\n";
        cout << "Please enter '2' or 'login' for login\nYour choice is: ";
        cin >> choice;
        cin.ignore(MAX_STRING_LENGTH,'\n');

        // 转换为小写以便比较
        transform(choice.begin(), choice.end(), choice.begin(), ::tolower);

        int num1;
        while(true) {
            if(choice == "1" || choice == "register") {
                num1 = 1;
                break;
            }
            else if(choice == "2" || choice == "login") {
                num1 = 2;
                break;
            }
            else {
                cout << endl;
                cout << "Invalid input! Please enter either:\n";
                cout << "- '1' or 'register' for registration\n";
                cout << "- '2' or 'login' for login\n";
                cout << "Your choice: ";
                cin >> choice;
                cin.ignore(MAX_STRING_LENGTH,'\n');
                transform(choice.begin(), choice.end(), choice.begin(), ::tolower);
            }
        }

        memset(recvMessage, '\0', sizeof(recvMessage));
        sendMessage.clear();
        switch(num1){
            //Register
            case 1:
            {
                string userName;
                string deposit;

                cout << "Please enter user's account name: ";
                cin >> userName;
                cin.ignore(MAX_STRING_LENGTH,'\n');

                cout << "Please enter deposit amount: ";
                cin >> deposit;
                cin.ignore(MAX_STRING_LENGTH,'\n');

                sendMessage = "REGISTER#" + userName + "#"+ deposit;
                SSL_write(ssl, sendMessage.c_str(), sendMessage.length());
                SSL_read(ssl, &recvMessage, sizeof(recvMessage));
                cout << recvMessage;
                break;
            }
            //Login
            case 2:
            {
                string userName;
                string portNum;

                cout << "Please enter user's account name: ";
                cin >> userName;
                cin.ignore(MAX_STRING_LENGTH,'\n');

                cout << "Please enter the client's port number: ";
                cin >> portNum;
                cin.ignore(MAX_STRING_LENGTH,'\n');
                while (stoi(portNum) < 1025 || stoi(portNum) > 65535)
                {
                    cout << "Port Number should be in range 1025 ~ 65535.\n";
                    cout << "Please enter the client's port number: ";
                    cin >> portNum;
                    cin.ignore(MAX_STRING_LENGTH,'\n');
                }

                sendMessage = userName + "#" + portNum;
                SSL_write(ssl, sendMessage.c_str(), sizeof(sendMessage));
                SSL_read(ssl, &recvMessage, sizeof(recvMessage));
                cout << recvMessage;

                if(strcmp(recvMessage,"220 AUTH_FAIL\n") == 0){
                    cout << endl;
                    cout << "This account has been logged in!" << endl; 
                    cout << "OR The account haven't been registered!"<< endl;
                    cout << "Please ask the server for more information." << endl;
                    exit(EXIT_FAILURE);
                }
                else{
                    pid_t pid;
                    pid = fork();
                    if(pid < 0){
                        cout << "fork doesn't exist!!";
                    }
                    else if (pid == 0){//I'm child fork, I'm listening

                        SSL_CTX* ctx_B2A = InitServerCTX();
                        LoadCertificates(ctx_B2A);

                        int sock_toListen = 0;
                        sock_toListen = socket(AF_INET, SOCK_STREAM, 0);

                        if (sock_toListen == -1){
                            cout << "Fail to create a socket!!" << endl;
                        }

                        //Setting socket information
                        struct sockaddr_in sock_toListen_info;
                        sock_toListen_info.sin_family = AF_INET;//IPv4
                        sock_toListen_info.sin_addr.s_addr = inet_addr("127.0.0.1");
                        sock_toListen_info.sin_port = htons(atoi(portNum.c_str()));

                        int isbind = bind(sock_toListen, (struct sockaddr*) &sock_toListen_info, sizeof(sock_toListen_info));
                        if (isbind < 0){
                            cout << "Failed to bind!!\n";
                            exit(EXIT_FAILURE);
                        }  
                        listen(sock_toListen, LISTEN_BACKLOG);
                        while(true){
                            int sock_forClient;                            
                            sock_forClient = accept(sock_toListen, NULL, NULL);
                            if(sock_forClient == -1){
                                cout << "Fail to accept!";
                                close(sock_forClient);
                                continue;
                            }
                            else{
                                SSL* ssl_B2A = SSL_new(ctx_B2A);
                                SSL_set_fd(ssl_B2A, sock_forClient);
                                if (SSL_accept(ssl_B2A) == -1){
                                    ERR_print_errors_fp(stderr);
                                    close(sock_forClient);
                                    continue;
                                }

                                ShowCerts(ssl_B2A);
                                memset(recvMessage, '\0', sizeof(recvMessage));
                                string sendToPeer = "Connected to peer!!!\n";

                                SSL_write(ssl_B2A, sendToPeer.c_str(), sizeof(sendToPeer));
                                SSL_read(ssl_B2A, &recvMessage, sizeof(recvMessage));

                                cout << "\n===========Transaction Request===========\n\n" << recvMessage << "\n========================================\n\n";
                                memset(recvMessage, '\0', sizeof(recvMessage));

                                SSL_shutdown(ssl_B2A);
                                SSL_free(ssl_B2A);
                                close(sock_forClient);
                            }
                        } 
                        cout << "child say goodbye ~ " << endl; 
                    }
                    else{//I'm parent fork
                        while(true){
                            string choice;
                            memset(recvMessage, '\0', sizeof(recvMessage));
                            sendMessage.clear();
                            cout << "\n======================\n\nChoose a function:\n";
                            cout << "1 or 'list': Query Accounts information\n";
                            cout << "2 or 'exit': Exit\n";
                            cout << "3 or 'trans': Micropayment transaction\n";
                            cout << "Your choice: ";
                            cin >> choice;
                            cin.ignore(MAX_STRING_LENGTH,'\n');

                            // 转换为小写以便比较
                            transform(choice.begin(), choice.end(), choice.begin(), ::tolower);

                            int num2;
                            while(true) {
                                if(choice == "1" || choice == "list") {
                                    num2 = 1;
                                    break;
                                }
                                else if(choice == "2" || choice == "exit") {
                                    num2 = 2;
                                    break;
                                }
                                else if(choice == "3" || choice == "trans") {
                                    num2 = 3;
                                    break;
                                }
                                else {
                                    cout << endl;
                                    cout << "Invalid input! Please enter either:\n";
                                    cout << "- '1' or 'list' for Query Accounts information\n";
                                    cout << "- '2' or 'exit' for Exit\n";
                                    cout << "- '3' or 'trans' for Micropayment transaction\n";
                                    cout << "Your choice: ";
                                    cin >> choice;
                                    cin.ignore(MAX_STRING_LENGTH,'\n');
                                    transform(choice.begin(), choice.end(), choice.begin(), ::tolower);
                                }
                            }

                            switch (num2){
                                //Query Accounts information
                                case 1:
                                {
                                    sendMessage = "List";
                                    SSL_write(ssl, sendMessage.c_str(), sendMessage.length());

                                    int readLen;
                                    do {
                                        readLen = SSL_read(ssl, &recvMessage, sizeof(recvMessage));
                                    } while(readLen <= 0 && SSL_want_read(ssl));

                                    cout << recvMessage;
                                    cout << "======================\n\n";  // 添加分隔线
                                    break;                
                                }

                                //Exit
                                case 2:
                                {
                                    sendMessage = "Exit";
                                    SSL_write(ssl, sendMessage.c_str(), sizeof(sendMessage));
                                    SSL_read(ssl, &recvMessage, sizeof(recvMessage));
                                    cout << recvMessage;               
                                    break;
                                }

                                //Micropayment transaction
                                case 3:
                                {  
                                    //create socket to connect with other's child
                                    SSL_CTX* ctx_toPeer = InitClientCTX();
                                    LoadCertificates(ctx_toPeer);

                                    int socket_toPeer = 0;
                                    socket_toPeer = socket(AF_INET, SOCK_STREAM, 0);

                                    if (socket_toPeer == -1){
                                        cout << "Fail to create a socket to peer!!" << endl;
                                    }

                                    string peerName;
                                    cout << "Who do you want to transact with? ";
                                    cin >> peerName;
                                    cin.ignore(MAX_STRING_LENGTH,'\n');
                                    // trans to self
                                    if(peerName == userName) {  
                                        cout << "Error: Cannot transfer money to yourself!" << endl;
                                        continue;
                                    }
                                    //take list to parse
                                    SSL_write(ssl, "List", sizeof("List"));
                                    SSL_read(ssl, &recvMessage, sizeof(recvMessage));

                                    // parse server's list
                                    string to_parse(recvMessage);
                                    int account_list_begin = 0;

                                    // account 
                                    while (to_parse[account_list_begin++] != '\n') {
                                        continue;
                                    }

                                    // Public key (skip 10 lines)
                                    for(int i = 0; i < 10; i++) {
                                        while (to_parse[account_list_begin++] != '\n') {
                                            continue;
                                        }
                                    }

                                    // user amount
                                    while (to_parse[account_list_begin++] != '\n') {
                                        continue;
                                    }

                                    string peerIP = "";
                                    string peerPort = "";
                                    string temp = "";
                                    while ((peerIP == "" && peerPort == "") && account_list_begin < to_parse.length())
                                    {
                                        // parse name
                                        while (to_parse[account_list_begin] != '#') { 
                                            temp += to_parse[account_list_begin];
                                            account_list_begin++;
                                        }
                                        account_list_begin++;
                                        if (temp == peerName) {
                                            // parse ip
                                            while (to_parse[account_list_begin] != '#') { 
                                                peerIP += to_parse[account_list_begin];
                                                account_list_begin++;
                                            }
                                            account_list_begin++;
                                            // parse port
                                            while (to_parse[account_list_begin] != '\n') { 
                                                peerPort += to_parse[account_list_begin];
                                                account_list_begin++;
                                            }
                                            account_list_begin++;
                                            break;
                                        }
                                        else { 
                                            // pass this line
                                            temp = "";
                                            while (to_parse[account_list_begin++] != '\n') { 
                                                continue;
                                            }
                                        }
                                    }
                                    if(temp != peerName){
                                        cout << "client hasn't logged in!" << endl;
                                        continue;
                                    }
                                    //end parsing



                                    //Setting socket information
                                    struct sockaddr_in sock_toPeer_info;
                                    sock_toPeer_info.sin_family = AF_INET;//IPv4
                                    sock_toPeer_info.sin_addr.s_addr = inet_addr(peerIP.c_str()); //"127.0.0.1" 
                                    sock_toPeer_info.sin_port = htons(atoi(peerPort.c_str()));
                                    cout << endl;
                                    cout << "List Received:" << endl;
                                    cout << "peer ip: " << peerIP << endl;;
                                    cout << "peer port: " << peerPort << endl;
                                    cout << endl;

                                    // establish a connection
                                    isConnect = connect(socket_toPeer, (struct sockaddr*)&sock_toPeer_info, sizeof(sock_toPeer_info));
                                    SSL* ssl_toPeer;
                                    if(isConnect == -1){
                                        cout << "Fail to connect with peer!!" << endl;
                                        exit(EXIT_FAILURE);
                                        close(socket_toPeer);
                                    }
                                     else{
                                        // generate a new SSL based on ctx
                                        ssl_toPeer = SSL_new(ctx_toPeer);
                                        SSL_set_fd(ssl_toPeer, socket_toPeer);
                                        //establish SSL connection
                                        if (SSL_connect(ssl_toPeer) == -1){
                                            ERR_print_errors_fp(stderr);
                                        }
                                        else{
                                            printf("Connected with %s encryption\n", SSL_get_cipher(ssl_toPeer));
                                            ShowCerts(ssl_toPeer);
                                        }  
                                    }

                                    memset(recvMessage, '\0', sizeof(recvMessage));
                                    SSL_read(ssl_toPeer, &recvMessage, sizeof(recvMessage));
                                    cout << recvMessage << endl;

                                    string transFee;
                                    cout << "How much do you want to transact? ";
                                    try{
                                        cin >> transFee;
                                    }
                                    catch(const out_of_range& orr){
                                        cout << "Out of Range error: " << orr.what() << endl;
                                        cout << "OVER LIMIT: single transaction limit is 1 ~ 100000. Try again: ";
                                        cin >> transFee;
                                    }
                                    try{
                                        while(stoi(transFee) > 100000 || stoi(transFee) <= 0){
                                            cout << "OVER LIMIT: single transaction limit is 1 ~ 100000." << endl;
                                            cout << "Try again: " << endl;
                                            cin >> transFee;
                                        }
                                    }
                                    catch(const out_of_range& orr){
                                        cout << "Out of Range error: " << orr.what() << endl;
                                        cout << "OVER LIMIT: single transaction limit is 1 ~ 100000. Try again: ";
                                        cin >> transFee;
                                    }

                                    sendMessage.clear();
                                    sendMessage = userName + "#" + transFee + "#" + peerName + "&";

                                    //send message to peer
                                    SSL_write(ssl_toPeer, sendMessage.c_str(), sizeof(sendMessage));
                                    close(socket_toPeer);

                                    //send message to server
                                    SSL_write(ssl, sendMessage.c_str(), sizeof(sendMessage));

                                    //read server's message
                                    memset(recvMessage, '\0', sizeof(recvMessage));
                                    SSL_read(ssl, &recvMessage, sizeof(recvMessage));
                                    cout << recvMessage << endl;

                                    SSL_shutdown(ssl_toPeer);
                                    SSL_free(ssl_toPeer);
                                    SSL_CTX_free(ctx_toPeer);
                                    break;
                                }
                            }
                            //Exit
                            if(num2 == 2){
                                if(strstr(recvMessage, "Bye\n") != NULL){
                                    break;
                                }
                            }
                        }

                    }
                }
                break;
            }    
        }
    }
    close(socket_d);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}