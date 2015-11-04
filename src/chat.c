#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#ifdef __VMS
#include <socket.h>
#include <inet.h>
 
#include <in.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
 
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define RETURN_NULL(x)    if ((x)==NULL) exit (1)
#define RETURN_ERR(err,s) if ((err)==-1) { perror(s); return 0; }
#define RETURN_SSL(err)   if ((err)==-1) { ERR_print_errors_fp(stderr); return 0; }
 
#define RSA_CLIENT_CERT         "fd.crt"
#define RSA_CLIENT_KEY          "fd.key"
 
#define ON      1
#define OFF     0
static int active = 1; 

void checkIfBye(char* message) {
	if ((strncmp("/bye", message, 4) == 0) ||
        (strncmp("/quit", message, 5) == 0)) {
		printf("bye sent!\n");
        active = 0;
        return;
    }
}

int main() {
	int             err;
	int             sock;
	struct          sockaddr_in server_addr;
	char            buf [4096];
	char            message[1204];

	SSL_CTX         *ctx;
	SSL             *ssl;
	const SSL_METHOD      *meth;

	short int       s_port = 9965;
	const char      *s_ipaddr = "127.0.0.1";

	/*----------------------------------------------------------*/


	/* Load encryption & hashing algorithms for the SSL program */
	SSL_library_init();

	/* Load the error strings for SSL & CRYPTO APIs */
	SSL_load_error_strings();

	/* Create an SSL_METHOD structure (choose an SSL/TLS protocol version) */
	meth = TLSv1_method();

	/* Create an SSL_CTX structure */
	ctx = SSL_CTX_new(meth);
	RETURN_NULL(ctx);

	/* ------------------------------------------------------------- */
	/* Set up a TCP socket */
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	memset (&server_addr, '\0', sizeof(server_addr));
	server_addr.sin_family      = AF_INET;
	server_addr.sin_port        = htons(s_port);       /* Server Port number */
	server_addr.sin_addr.s_addr = inet_addr(s_ipaddr); /* Server IP */

	/* Establish a TCP/IP connection to the SSL client */
	err = connect(sock, (struct sockaddr*) &server_addr, sizeof(server_addr)); 
	RETURN_ERR(err, "connect");

	/* ----------------------------------------------- */

	/* An SSL structure is created */
	ssl = SSL_new(ctx);
	RETURN_NULL(ssl);

	/* Assign the socket into the SSL structure (SSL and socket without BIO) */
	SSL_set_fd(ssl, sock);

	/* Perform SSL Handshake on the SSL client */
	err = SSL_connect(ssl);
	RETURN_SSL(err);

	/* Receive Welcome message */
	err = SSL_read(ssl, buf, sizeof(buf)-1);                     
	RETURN_SSL(err);
	buf[err] = '\0';
	/*-------- DATA EXCHANGE - send message and receive reply. -------*/
 	
 	while(active) {
 		printf("> ");
  		fgets(message, 80, stdin);
		checkIfBye(message);

  		/* Send data to the SSL server */
		err = SSL_write(ssl, message, strlen(message));  
		RETURN_SSL(err);

		/* Receive data from the SSL server */
		err = SSL_read(ssl, buf, sizeof(buf)-1);                     
		RETURN_SSL(err);

		buf[err] = '\0';
		printf ("Received %d chars:'%s'\n", err, buf);
	}
	/*--------------- SSL closure ---------------*/
	/* Shutdown the client side of the SSL connection */
	err = SSL_shutdown(ssl);
	RETURN_SSL(err);

	/* Terminate communication on a socket */
	err = close(sock);
	RETURN_ERR(err, "close");

	/* Free the SSL structure */
	SSL_free(ssl);

	/* Free the SSL_CTX structure */
	SSL_CTX_free(ctx);
	return 0;
}