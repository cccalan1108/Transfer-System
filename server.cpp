#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <arpa/inet.h>
#include <string>
#include <fstream>
#include <bits/stdc++.h>
#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <pthread.h>
#include <queue>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
using namespace std;

#define MAX_STRING_LENGTH 200
#define LISTEN_BACKLOG 10
#define CSTRING_MAX_SIZE 500
#define THREAD_NUM 2

// ssl
SSL_CTX* InitClientCTX();
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


// user, userList
class User{
public:
    User();
    User(string name, int money, string IP, string port, bool isOnline);
    string getName();
    string getIP();
    string getPort();
    int getMoney();
    bool getIsOnline();

    void setName(const string name);
    void setIP(const string IP);
    void setPort(const string port);
    void setMoney(const int money);
    void setIsOnline(const bool online);
    friend class UserList;
private:
    string port;
    string IP;
    string name;
    int money;
    bool isOnline;
};

class UserList{
private:
    vector<User*> usersListPtr;
    SSL_CTX* ctx;
public:
    int getOnlineNum();
    UserList();
    void setSSLContext(SSL_CTX* ctx) { this->ctx = ctx; }
    User* findUser(string name);
    bool regiserUpdate(string clientMessage);
    User* loginUpdate(string clientMessage, Client aClient);
    string list(User* aUser);
    bool exit(User* aUser);
    int transact(string clientMessage);
};
User::User(){
    this->money = 0;
    this->name = "";
    this->IP = "";
    this->port = "";
    this->isOnline = false;
}

User::User(string name, int money, string IP, string port, bool isOnline){
    this->money = money;
    this->name = name;
    this->IP = IP;
    this->port = port;
    this->isOnline = isOnline;  
}

string User::getName(){
    return this->name;
}

string User::getIP(){
    return this->IP;
}

string User::getPort(){
    return this->port;
}

int User::getMoney(){
    return this->money;
}

bool User::getIsOnline(){
    return this->isOnline;
}

void User::setName(const string name)
{
    this->name = name;
}

void User::setIP(const string IP){
    this->IP = IP;
}

void User::setPort(const string port)
{
    this->port = port;
}

void User::setMoney(const int money){
    this->money = money;
}

void User::setIsOnline(const bool online)
{
    this->isOnline = online;
}


UserList::UserList(){
    usersListPtr.clear();
    ctx = nullptr;
}

User* UserList::findUser(string userName){
    int len = this->usersListPtr.size();
    for(int i = 0; i < len; i++){
        if(this->usersListPtr[i]->name == userName){
            return this->usersListPtr[i];
        }
    }
    return nullptr;
}

int UserList::getOnlineNum(){
    int cnt = 0;
    int len = this->usersListPtr.size();
    for(int i = 0; i < len ; i++){
        if(this->usersListPtr[i]->getIsOnline()){
            cnt++;
        }
    }
    return cnt;
}

bool UserList::regiserUpdate(string clientMessage){
    string mainMsg = clientMessage.substr(9);
    int balanceMsg = mainMsg.find("#") + 1;

    string name = mainMsg.substr(0, balanceMsg - 1);
    string balance = mainMsg.substr(balanceMsg);
    int balance_int = atoi(balance.c_str());

    if (this->findUser(name) == nullptr){
        User* newUser = new User(name, balance_int, "", "", false);
        this->usersListPtr.push_back(newUser);
        return true;
    }
    else{
        return false;
    }
}

User* UserList::loginUpdate(string clientMessage, Client aClient){
    int portMsg = clientMessage.find("#") + 1;
    string name = clientMessage.substr(0, portMsg - 1);
    string port = clientMessage.substr(portMsg);

    try {
        int portNum = stoi(port);
        if(portNum < 1025 || portNum > 65535) {
            cout << "Invalid port number!" << endl;
            return nullptr;
        }

        port = to_string(portNum);  
    } catch(...) {
        cout << "Invalid port format!" << endl;
        return nullptr;
    }

    User* aUser = this->findUser(name);
    if (aUser != nullptr){
        if(aUser->isOnline == false){
            aUser->setIsOnline(true);
            aUser->setPort(port); 
            aUser->setIP(aClient.getIP());
            return aUser;
        }
        else{
            cout << "This account has been logged in!";
            return nullptr;
        }    
    }
    else{
        cout << "The account haven't been registered!\n";
        return nullptr;
    }  
    return nullptr;
}

string UserList::list(User* aUser){
    int len = this->usersListPtr.size();

    string listMessage = "";
    listMessage += to_string(aUser->getMoney());
    listMessage += "\n";

    BIO *bio = BIO_new(BIO_s_mem());
    EVP_PKEY *pkey = SSL_CTX_get0_privatekey(ctx);
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    PEM_write_bio_RSA_PUBKEY(bio, rsa);

    char *pem_key;
    long pem_size = BIO_get_mem_data(bio, &pem_key);
    string publicKey(pem_key, pem_size);

    listMessage += publicKey;
    listMessage += "\n";

    listMessage += to_string(this->getOnlineNum());
    listMessage += "\n";

    for(int i = 0; i < len; i++){
        if((usersListPtr[i]->isOnline) == true){
            listMessage += usersListPtr[i]->getName();
            listMessage += "#";
            listMessage += usersListPtr[i]->getIP();
            listMessage += "#";
            listMessage += to_string(stoi(usersListPtr[i]->getPort()));
            listMessage += "\n";
        }
    }
    cout << "list Message Preview: " << listMessage << endl;
    BIO_free(bio);
    RSA_free(rsa);
    return listMessage;
}

bool UserList::exit(User* aUser){
    if(aUser->getIsOnline() == true){
        aUser->setIsOnline(false);
        return true;
    }
    return false;
}

int UserList::transact(string clientMessage){

    //parse transact message
    int foundAt = clientMessage.find("#");
    string pay_peer = clientMessage.substr(0, foundAt);
    string temp = clientMessage.substr(foundAt + 1, clientMessage.length());
    foundAt = temp.find("#");
    string tranAmount_str = temp.substr(0, foundAt);
    temp = temp.substr(foundAt + 1, temp.length());
    string receive_peer = temp.substr(0, temp.find("&"));
    cout << endl;
    cout << "pay peer: " << pay_peer << endl;
    cout << "tranAmount str: " << tranAmount_str << endl;
    cout << "receive peer: " << receive_peer << endl;
    cout << endl;
    int tranAmount = stoi(tranAmount_str);

    //update transaction information in server 
    User* payUser = this->findUser(pay_peer);
    User* receiveUser = this->findUser(receive_peer);

    int scenario = 0; 
    if(payUser->getMoney() - tranAmount < 0){
        scenario = 1;
        cout << "CANNOT TRANSACT: pay_peer doesn't have enough money." << endl;
    }
    if(receiveUser->getMoney() > INT_MAX - tranAmount){
        scenario = 2;
        cout << "CANNOT TRANSACT: over deposit limit." << endl;
    }

    if(scenario == 0){
        payUser->setMoney(payUser->getMoney() - tranAmount);
        receiveUser->setMoney(receiveUser->getMoney() + tranAmount);
        cout << "=================================" << endl;
        cout << "transaction success!!" << endl;
        cout << "=================================" << endl;
        return 0;
    }
    else if(scenario == 1){
        return 1;
    }
    else{
        return 2;
    }
}


// threadpool class
class ThreadPool{
private:
    int threadNum;
    pthread_mutex_t mutex; 
    pthread_cond_t condition_var;
    pthread_t* threads;
    queue<Client> waitingQueue;
    static void* interface(void* thread);
    void handle(void* thread);
    void function(Client aClient);
    UserList userMap;
    SSL_CTX* ctx;
public:
    ThreadPool(SSL_CTX* ctx);
    void connect(Client &c);
    void createThreads();
};

ThreadPool::ThreadPool(SSL_CTX* ctx) {
    this->threadNum = THREAD_NUM;
    this->threads = new pthread_t[this->threadNum];
    int isMutex = pthread_mutex_init(&(this->mutex), NULL);
    if(isMutex != 0){
        cout << "Error on locking!\n";
    }
    this->condition_var = PTHREAD_COND_INITIALIZER;
    this->ctx = ctx;
    userMap.setSSLContext(ctx);
}

void ThreadPool::connect(Client &c){
    pthread_mutex_lock(&(this->mutex));
    this->waitingQueue.push(c);
    pthread_mutex_unlock(&(this->mutex));
}

void ThreadPool::createThreads(){
    for(int i = 0; i < threadNum; i++){
        pthread_create(&(this->threads[i]), NULL, this->interface, this);
    }
}

void* ThreadPool::interface(void* thread){
    ThreadPool* _this = (ThreadPool*)thread;
    _this->handle(thread);
    return nullptr;
}

void ThreadPool::handle(void* thread){
    ThreadPool* _this = (ThreadPool*)thread;
    while(true){
        Client aClient;
        pthread_mutex_lock(&(this->mutex));
        if(!(this->waitingQueue.empty())){
            aClient = this->waitingQueue.front();
            this->waitingQueue.pop();
        }
        pthread_mutex_unlock(&(this->mutex));
        _this->function(aClient);

    }
}

void ThreadPool::function(Client aClient){
    if(aClient.getSSL() == nullptr){
         return;
    }
    cout << "Handling...." << endl;
    SSL* clientSSL = aClient.getSSL();
    char recvMessage[CSTRING_MAX_SIZE] = {};
    memset(recvMessage, '\0', sizeof(recvMessage)); 

    char serverMessage[CSTRING_MAX_SIZE*10] = {};
    memset(serverMessage, '\0', sizeof(serverMessage));
    string msg = "Connection Acceptted !";
    SSL_write(clientSSL, msg.c_str(), msg.length());

    User* aUser = nullptr;
    string message = "";
    while(true){
        SSL_read(clientSSL, recvMessage, sizeof(recvMessage));
        string clientMessage(recvMessage); 
        cout << "Client Message: " << clientMessage << endl;
        memset(recvMessage, '\0', sizeof(recvMessage));

        int function = 0;
        //function 1: register, 2: login, 3: query, 4:Exit, 5:microTransaction
        if(clientMessage.find("REGISTER") != string::npos){    
            function = 1;
        }

        else if(clientMessage.find("&") != string::npos){
            cout << "Server is updating transaction amount..." << endl;
            function = 5;
        }

        else if(clientMessage.find("#") != string::npos){
            function = 2;
        }

        if(clientMessage.find("Exit") != string::npos){
            function = 3;
        }

        if(clientMessage.find("List") != string::npos){
            function = 4;
        }

        //Register
        if(function == 1){
            bool isSuccess = userMap.regiserUpdate(clientMessage);
            //userName has been occupied
            if(!isSuccess){
                message = "210 FAIL\n";
                cout << "Sorry, this name has been registered. Please try another one.\n";
                SSL_write(clientSSL, message.c_str(), message.length());
            }
            else{
                message = "100 OK\n";
                cout << "Successfully register\n";
                SSL_write(clientSSL, message.c_str(), message.length());
            }
        }

        //Login
        else if (function == 2){
            aUser = userMap.loginUpdate(clientMessage, aClient);
            cout << "Updated..." << endl;

            //have logged in  or haven't registered
            if(aUser == nullptr){ 
                message = "220 AUTH_FAIL\n";
                SSL_write(clientSSL, message.c_str(), message.length());
            }
            else{
                message = userMap.list(aUser);
                SSL_write(clientSSL, message.c_str(), message.length());
                cout << "Successfully login!\n";
            }         
        } 

        //Exit
        else if (function == 3){
            bool isExit = userMap.exit(aUser);
            if(isExit){
                message = "Bye\n";
                cout << message;
                SSL_write(clientSSL, message.c_str(), message.length());
            }
            else{
                cout << "Fail to exit!" << endl;
            }
        }

        //Online List
        else if(function == 4){
            message = userMap.list(aUser);
            int writeLen = SSL_write(clientSSL, message.c_str(), message.length());
            if(writeLen <= 0) {
                cout << "Error sending list message" << endl;
                SSL_write(clientSSL, message.c_str(), message.length());
            }
        }

        //Microtransaction
        else if(function == 5){
            int tranStatus = userMap.transact(clientMessage);
            if(tranStatus == 0){
                message = "Transaction Succeed.";
                SSL_write(clientSSL, message.c_str(), message.length());
            }
            else if(tranStatus == 1){
                message = "CANNOT TRANSACT: pay_peer doesn't have enough money. Try again!";
                SSL_write(clientSSL, message.c_str(), message.length());
            }
            else{
                message = "CANNOT TRANSACT: over deposit limit. Try again!";
                SSL_write(clientSSL, message.c_str(), message.length());
            }
        }

        else {
            if (aUser->getIsOnline())
            {
                message = "Server Message: Client disconnected\n";
                cout << message;
                message.clear();
                break;
            }
        }

        cout << "Server Message: " << message;
        message.clear();
    }

    SSL_shutdown(clientSSL);
    SSL_free(clientSSL);
    close(aClient.sockfd);
}


int main(){

    char CertFile [] = "./Cert_s.crt";
    char KeyFile [] = "./Key_s.key";

    SSL_CTX* ctx = InitServerCTX();
    LoadCertificates(ctx);

    int serverPort;
    cout << "Please enter server's port: ";
    cin >> serverPort;
    int sockfd = 0;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    while(sockfd == -1){
        cout << "Fail to create a socket!";
        cout << "Please enter server's port: ";
        cin >> serverPort;
        int sockfd = 0;
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
    }

    struct sockaddr_in clientInfo; 
    struct sockaddr_in serverInfo;
    int clientAddrlen = sizeof(clientInfo);
    bzero(&serverInfo, sizeof(serverInfo));

    serverInfo.sin_family = PF_INET;
    serverInfo.sin_addr.s_addr = INADDR_ANY;
    serverInfo.sin_port = htons(serverPort);

    int isBind = bind(sockfd, (struct sockaddr*) &serverInfo, sizeof(serverInfo));
    if (isBind < 0){
        cout << "Failed to bind!\n";
        exit(1);
    }  

    listen(sockfd, LISTEN_BACKLOG);
    cout << "Waiting for connection......" << endl;

    ThreadPool threadPool(ctx);
    threadPool.createThreads();

    while(true){
        int forClientSockfd = accept(sockfd, (struct sockaddr*)&clientInfo, (socklen_t*)&clientAddrlen);//sizeof(clientAddrlen)
        if(forClientSockfd == -1){
            cout << "Fail to accept!";
            close(forClientSockfd);
            continue;
        }
        else{
            SSL* ssl = SSL_new(ctx);
            SSL_set_fd(ssl, forClientSockfd);
            if (SSL_accept(ssl) == -1){
                ERR_print_errors_fp(stderr);
                close(forClientSockfd);
                continue;
            }
            ShowCerts(ssl);
            // ssl substitutes socket to communicate with client

            char sendToClientMessage[] = {"Connecting...\n"};
            SSL_write(ssl, sendToClientMessage, sizeof(sendToClientMessage));

            //extract client ip
            struct sockaddr_in* pV4Addr = (struct sockaddr_in *)&clientInfo;
            struct in_addr ipAddr = pV4Addr -> sin_addr;

            //Getting IP address "string"
            char clientIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ipAddr, clientIP,INET_ADDRSTRLEN);

            //creat a client
            string ip_addr(clientIP);
            Client client(ip_addr, forClientSockfd, ssl);
            threadPool.connect(client);//enter threadPoolClass
        }
    }

    return 0;
}