#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
 
#ifdef __VMS
#include <types.h>
#include <socket.h>
#include <in.h>
#include <inet.h>
 
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
 
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/time.h>
#include <time.h>
#include <glib.h>
 
#define RSA_SERVER_CERT       "fd.crt"
#define RSA_SERVER_KEY        "fd.key"

#define RETURN_NULL(x)    if ((x)==NULL) return 0;
#define RETURN_ERR(err,s) if ((err)==-1) { perror(s); return 0; }
#define RETURN_SSL(err)   if ((err)==-1) { ERR_print_errors_fp(stderr); return 0; }

typedef struct {
    char ip[64];
    char port[8];
} Client;

Client* clientLog;

void writeToLog(int connecting) {
    FILE *logFile;
    logFile = fopen("clients.log", "a");
 
    time_t timestamp;
    time(&timestamp);
    char buf[sizeof("2011-10-08T07:07:09Z")];
    strftime(buf, sizeof(buf), "%FT%TZ", gmtime(&timestamp));

    GString *stringBuilder = g_string_new(buf);
    stringBuilder = g_string_append(stringBuilder, " : ");
    stringBuilder = g_string_append(stringBuilder, clientLog->ip);
    stringBuilder = g_string_append(stringBuilder, ":");
    stringBuilder = g_string_append(stringBuilder, clientLog->port);
    
    if(connecting)
        stringBuilder = g_string_append(stringBuilder, " connected\n");
    else
        stringBuilder = g_string_append(stringBuilder, " disconnected\n");
    
    if(logFile == NULL) {
        printf("Error when opening file\n");
    }
    else {
        fprintf(logFile, "%s\n", stringBuilder->str);
    }

    fclose(logFile);
    g_string_free(stringBuilder, 1);
}

int checkIfBye(char* message) {
    if ((strncmp("/bye", message, 4) == 0) ||
        (strncmp("/quit", message, 5) == 0)) {
        return 1;
    }
    return 0;
}

int main()
{
    int           err;
    int           listen_sock;
    int           sock;
    struct        sockaddr_in sa_serv;
    struct        sockaddr_in sa_cli;
    socklen_t     client_len;
    char          buf[4096];

    SSL_CTX       *ctx;
    SSL           *ssl = NULL;
    const SSL_METHOD    *meth;
    short int     s_port = 9965;
    fd_set read_fd_set;
    SSL* sslArray[1024];
    
    for(int i = 0; i < 1024; ++i) {
        sslArray[i] = NULL;
    }

    /*----------------------------------------------------------------*/
    /* Load encryption & hashing algorithms for the SSL program */
    SSL_library_init();
    /* Load the error strings for SSL & CRYPTO APIs */
    SSL_load_error_strings();
    /* Create a SSL_METHOD structure (choose a SSL/TLS protocol version) */
    meth = TLSv1_method();
    /* Create a SSL_CTX structure */
    ctx = SSL_CTX_new(meth);

    if(!ctx) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    /* Load the server certificate into the SSL_CTX structure */
    if(SSL_CTX_use_certificate_file(ctx, RSA_SERVER_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    /* Load the private-key corresponding to the server certificate */
    if(SSL_CTX_use_PrivateKey_file(ctx, RSA_SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    /* Check if the server certificate and private-key matches */
    if(!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr,"Private key does not match the certificate public key\n");
        return 0;
    }

    /* ----------------------------------------------- */
    /* Set up a TCP socket */
    listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    RETURN_ERR(listen_sock, "socket");
    memset (&sa_serv, '\0', sizeof(sa_serv));
    sa_serv.sin_family      = AF_INET;
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    sa_serv.sin_port        = htons (s_port);          /* Server Port number */
    err = bind(listen_sock, (struct sockaddr*)&sa_serv,sizeof(sa_serv));

    RETURN_ERR(err, "bind");

    /* Wait for an incoming TCP connection. */
    err = listen(listen_sock, 1024);
    RETURN_ERR(err, "listen");
    client_len = sizeof(sa_cli);

    while(1) {
        FD_ZERO (&read_fd_set);
        FD_SET (listen_sock, &read_fd_set);

        for(int i = 0; i < 1024; i++) {
            if(sslArray[i] != NULL) {
                FD_SET(i, &read_fd_set);
            }
        }

        if(select(FD_SETSIZE, &read_fd_set, NULL,  NULL, NULL) < 0) {
            perror("select");
            exit (1);
        } 

        if(FD_ISSET(listen_sock, &read_fd_set)){
            /* Socket for a TCP/IP connection is created */
            sock = accept(listen_sock, (struct sockaddr*)&sa_cli, &client_len);
            RETURN_ERR(sock, "accept");
            /* TCP connection is ready. */
            /* A SSL structure is created */
            ssl = SSL_new(ctx);
            RETURN_NULL(ssl);

            /* Assign the socket into the SSL structure (SSL and socket without BIO) */
            SSL_set_fd(ssl, sock);

            /* Perform SSL Handshake on the SSL server */
            err = SSL_accept(ssl);
            RETURN_SSL(err);

            FD_SET(sock, &read_fd_set);

            printf("client nr %d just connected\n", sock);
            err = SSL_write(ssl, "Whalecum\n", strlen("Whalecum\n"));
            RETURN_SSL(err);

            clientLog = g_new0(Client, 1);
            strcpy(clientLog->ip, inet_ntoa(sa_cli.sin_addr));
            sprintf(clientLog->port, "%d", ntohs(sa_cli.sin_port));
            writeToLog(1);

            sslArray[sock] = ssl;
        }

        for(int i = 0 ; i < FD_SETSIZE; ++i) {
            if(FD_ISSET(i, &read_fd_set) && sslArray[i] != NULL) {
                printf("Index nr %d is active\n", i);
                /*------- DATA EXCHANGE - Receive message and send reply. -------*/
                /* Receive data from the SSL client */
                err = SSL_read(ssl, buf, sizeof(buf) - 1);
                RETURN_SSL(err);

                buf[err] = '\0';
                printf ("From %d: \nReceived %d chars: %s",i, err, buf);

                if (checkIfBye(buf)) {
                    /* user sent "\bye" */
                    err = SSL_write(ssl, "Goodbye!", 
                                strlen("Goodbye!"));
                    RETURN_SSL(err);

                    SSL_free(sslArray[i]);
                    sslArray[i] = NULL;
                    writeToLog(0);
                }

                /* Send data to the SSL client */
                err = SSL_write(ssl, "Roger from server", 
                                strlen("Roger from server"));
                RETURN_SSL(err);
            }
        }
    }

    /*--------------- SSL closure ---------------*/

    //writeToLog(0); // write to log that the client disconnected
    /* Shutdown this side (server) of the connection. */
    err = SSL_shutdown(ssl);
    RETURN_SSL(err);

    /* Terminate communication on a socket */
    err = close(sock);
    RETURN_ERR(err, "close");

    /* Freeing the allocated memory */
    for(int i = NULL; i < FD_SETSIZE; ++i) {
        SSL_free(sslArray[i]);
    }

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    g_free(clientLog);
}