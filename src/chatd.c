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
#include <ctype.h>
 
#define RSA_SERVER_CERT "fd.crt"
#define RSA_SERVER_KEY "fd.key"

#define RETURN_NULL(x)    if ((x)==NULL) {exit(1);}
#define RETURN_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define RETURN_SSL(err)   if ((err)==-1) { ERR_print_errors_fp(stderr); exit(1); }

/* Structs */
typedef struct {
    char username[64];
    char chatroom[64];
    int sock;
    SSL* ssl;
    char ip[64];
    char port[8];
} ClientInfo;

/* Globals */
ClientInfo*   clientInfo;
static GTree* usersTree;
static GTree* chatroomTree;
static int    max;
GString*      allUsers;
GString*      allRooms;

/* This can be used to build instances of GTree that index on
   the address of a connection. */
int sockaddr_in_cmp(const void *addr1, const void *addr2)
{
    const struct sockaddr_in *_addr1 = addr1;
    const struct sockaddr_in *_addr2 = addr2;

    /* If either of the pointers is NULL or the addresses
       belong to different families, we abort. */
    g_assert((_addr1 != NULL) && (_addr2 != NULL) &&
         (_addr1->sin_family == _addr2->sin_family));

    if (_addr1->sin_addr.s_addr < _addr2->sin_addr.s_addr) {
        return -1;
    } else if (_addr1->sin_addr.s_addr > _addr2->sin_addr.s_addr) {
        return 1;
    } else if (_addr1->sin_port < _addr2->sin_port) {
        return -1;
    } else if (_addr1->sin_port > _addr2->sin_port) {
        return 1;
    }
    return 0;
}

void writeToLog(int connecting) {
    FILE *logFile;
    logFile = fopen("clients.log", "a");
 
    time_t timestamp;
    time(&timestamp);
    char buf[sizeof("2011-10-08T07:07:09Z")];
    strftime(buf, sizeof(buf), "%FT%TZ", gmtime(&timestamp));

    GString *stringBuilder = g_string_new(buf);
    stringBuilder = g_string_append(stringBuilder, " : ");
    stringBuilder = g_string_append(stringBuilder, clientInfo->ip);
    stringBuilder = g_string_append(stringBuilder, ":");
    stringBuilder = g_string_append(stringBuilder, clientInfo->port);
    
    if(connecting)
        stringBuilder = g_string_append(stringBuilder, " connected\n");
    else {
        stringBuilder = g_string_append(stringBuilder, " disconnected\n");
    }
    
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

/*  */
static gint getListOfUsers(gpointer key, gpointer value, gpointer data) {
    /* getting rid of warning unused parameter */
    (void)key;
    (void)data;
    /* make the string that contains info about all users */
    ClientInfo* cliInf = (ClientInfo*)value;

    allUsers = g_string_append(allUsers, "\nUsername: ");
    allUsers = g_string_append(allUsers, cliInf->username);
    allUsers = g_string_append(allUsers, "\n    IP: ");
    allUsers = g_string_append(allUsers, cliInf->ip);
    allUsers = g_string_append(allUsers, "\n    Port: ");
    allUsers = g_string_append(allUsers, cliInf->port);
    allUsers = g_string_append(allUsers, "\n    Chatroom: ");
    allUsers = g_string_append(allUsers, cliInf->chatroom);
    allUsers = g_string_append(allUsers, "\n");
    return 0;
}

static gint getListOfChatrooms(gpointer key, gpointer value, gpointer data) {
    /* getting rid of warning unused parameter */
    (void)value;
    (void)data;

    allRooms = g_string_append(allRooms, key);
    allRooms = g_string_append(allRooms, "\n");
    return 0;
}

static void sendToUser(gpointer data, gpointer user_data) {
    char* message = user_data;
    ClientInfo* cliInf = (ClientInfo*)data;
    SSL_write(cliInf->ssl, message, strlen(message));
}

static gint treeTraversal(gpointer key, gpointer value, gpointer data) {
    char buf[1024];
    int err;

    /* Get the client info from the tree */
    ClientInfo* cliInf = (ClientInfo*)value;
    fd_set *read_fd_set = (fd_set*)data;

    if(FD_ISSET(cliInf->sock, read_fd_set)) {
        /*------- DATA EXCHANGE - Receive message and send reply. -------*/
        /* Receive data from the SSL client */
        err = SSL_read(cliInf->ssl, buf, sizeof(buf) - 1);
        RETURN_SSL(err);

        buf[err] = '\0';

        /* Check if the client sent "/bye" */
        if (checkIfBye(buf) || err < 1) {
            writeToLog(0);
            /*Pepperoni*/
            g_tree_remove(usersTree, key);
        }
        else if (strncmp("/who", buf, 4) == 0) {
            /* Check if the client sent "/who" */
            allUsers = g_string_new("");
            g_tree_foreach(usersTree, getListOfUsers, read_fd_set);

            SSL_write(cliInf->ssl, allUsers->str, strlen(allUsers->str));
            g_string_free(allUsers, 1);
        }
        else if (strncmp("/join", buf, 5) == 0) {
            /* Check if the client sent "/join room" */
            /* Get room name */
            char* room = g_new0(char, strlen(buf) - 5);
            int i = 5;
            while (buf[i] != '\0' && isspace(buf[i])) { i++; }
            strcpy(room, buf + i);

            /* remove the user from current chat room */
            GSList* currentList = g_tree_lookup(chatroomTree, cliInf->chatroom);
            currentList = g_slist_remove(currentList, cliInf);
            g_tree_insert(chatroomTree, cliInf->chatroom, currentList);

            /* add the user to the new room */
            GSList* userList = g_tree_lookup(chatroomTree, room);
            userList = g_slist_prepend(userList, cliInf);
            g_tree_insert(chatroomTree, room, userList);
            strcpy(cliInf->chatroom, room);
        
            /* Send a welcome message to chatroom */
            char msgString[128];
            sprintf(msgString, "Welcome to the chat room %s!\n", room);
            err = SSL_write(cliInf->ssl, msgString, strlen(msgString));
            RETURN_SSL(err);
        }
        else if (strncmp("/list", buf, 5) == 0) {
            /* Check if the client sent "/list" */
            allRooms = g_string_new("Available rooms:\n");
            g_tree_foreach(chatroomTree, getListOfChatrooms, NULL);

            SSL_write(cliInf->ssl, allRooms->str, strlen(allRooms->str));
            g_string_free(allRooms, 1);
        }
        else if (strncmp("/user", buf, 5) == 0) {
            /* Check if the client sent "/user" */
            int i = 5;
            char* user = g_new0(char, strlen(buf) - 5);
            /* Skip whitespace */
            while (buf[i] != '\0' && isspace(buf[i])) { i++; }
            strcpy(user, buf + i);
            printf("user just changed his user name to: %s\n", user);
        }
        else {
            /* Send all users in the same room the message */
            GSList* userList = g_tree_lookup(chatroomTree, cliInf->chatroom);
            g_slist_foreach(userList, sendToUser, buf);
        }

        if(cliInf->sock > max) {
            max = cliInf->sock;
        }
    }
    return 0;
}

static gint setFD(gpointer key, gpointer value, gpointer data) {
    /* getting rid of warning unused parameter */
    (void)key;

    ClientInfo* cliInf = (ClientInfo*)value;
    fd_set *read_fd_set = (fd_set*)data;
    FD_SET(cliInf->sock, read_fd_set);
    if(cliInf->sock > max) {
        max = cliInf->sock;
    }
    return 0;
}

/* Takes the new client makes a user and adds it to the tree */
void createUser(SSL_CTX *ctx, struct sockaddr_in sa_cli, int listen_sock) {
    /* Socket for a TCP/IP connection is created */
    int err;
    socklen_t client_len = sizeof(sa_cli);
    int sock = accept(listen_sock, (struct sockaddr*) &sa_cli, &client_len);
    RETURN_ERR(sock, "accept");

    /* TCP connection is ready. */
    /* A SSL structure is created */
    SSL *ssl = SSL_new(ctx);
    RETURN_NULL(ssl);

    /* Assign the socket into the SSL structure (SSL and socket without BIO) */
    SSL_set_fd(ssl, sock);

    /* Perform SSL Handshake on the SL server */
    err = SSL_accept(ssl);
    RETURN_SSL(err);

    /* Add the necessary info into clientInfo */
    clientInfo = g_new0(ClientInfo, 1);
    clientInfo->ssl = ssl;
    clientInfo->sock = sock;
    strcpy(clientInfo->username, "Anonymous");
    strcpy(clientInfo->chatroom, "public");
    strcpy(clientInfo->ip, inet_ntoa(sa_cli.sin_addr));
    sprintf(clientInfo->port, "%d", ntohs(sa_cli.sin_port));

    /* Write to clientlog.txt that the client connected */
    writeToLog(1);

    /* The user is added to the tree with the sockaddr as key and 
     * the client Info as value */
    struct sockaddr_in *key = g_new0(struct sockaddr_in, 1);
    memcpy(key, &sa_cli, sizeof(sa_cli));
    g_tree_insert(usersTree, key, clientInfo);

    /* add the user to the room public */
    GSList* roomList = g_tree_lookup(chatroomTree, "public");
    roomList = g_slist_prepend(roomList, clientInfo);
    g_tree_insert(chatroomTree, "public", roomList);

    /* Send a welcome message to the new client */
    err = SSL_write(ssl, "Welcome\n", strlen("Welcome\n"));
    RETURN_SSL(err);
}

int main(int argc, char **argv) {
    if(argc != 2) {
        printf("To run the client please only have a port number.\n");
        return 0;
    }
    int               err;
    int               listen_sock;
    struct            sockaddr_in sa_serv;
    struct            sockaddr_in sa_cli;
    SSL_CTX           *ctx;
    const SSL_METHOD  *meth;
    usersTree         = g_tree_new((GCompareFunc) sockaddr_in_cmp);
    chatroomTree      = g_tree_new((GCompareFunc) strcmp);
    short int         s_port = strtol(argv[1], NULL, 0);
    
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

    /* ---------------------clientLog-------------------------- */
    /* Set up a TCP socket */
    listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    RETURN_ERR(listen_sock, "socket");
    memset (&sa_serv, '\0', sizeof(sa_serv));
    sa_serv.sin_family      = AF_INET;
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    sa_serv.sin_port        = htons (s_port);          /* Server Port number */
    err = bind(listen_sock, (struct sockaddr*)&sa_serv, sizeof(sa_serv));

    RETURN_ERR(err, "bind");

    /* Wait for an incoming TCP connection. */
    err = listen(listen_sock, 1024);
    RETURN_ERR(err, "listen");

    /* insert the default chatroom "public" with no users */  
    g_tree_insert(chatroomTree, "public", NULL);
 
    while(1) {
        fd_set read_fd_set;
        FD_ZERO (&read_fd_set);
        FD_SET (listen_sock, &read_fd_set);

        /* Go through the tree and set FD on all of the clients */
        max = listen_sock;
        g_tree_foreach(usersTree, setFD, &read_fd_set);

        if(select(max + 1, &read_fd_set, NULL,  NULL, NULL) < 0) {
            perror("select");
            exit (1);
        } 

        /* A new client connected */
        if(FD_ISSET(listen_sock, &read_fd_set)){
            createUser(ctx, sa_cli, listen_sock);
        }

        /* Go through all clients and check if there is data to recieve 
         * See treeTraversal() for more info */
        g_tree_foreach(usersTree, treeTraversal, &read_fd_set);
    }

    /*--------------- SSL closure ---------------*/

    //writeToLog(0); // write to log that the client disconnected
    /* Shutdown this side (server) of the connection. */
    /*err = SSL_shutdown(ssl);
    RETURN_SSL(err);
*/
    /* Terminate communication on a socket */
    //err = close(sock);
    //RETURN_ERR(err, "close");

    /* Freeing the allocated memory */
    //SSL_free(ssl);
    //SSL_CTX_free(ctx);
}