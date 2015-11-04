/* A TCP echo server with timeouts.
 *
 * Note that you will not need to use select and the timeout for a
 * tftp server. However, select is also useful if you want to receive
 * from multiple sockets at the same time. Read the documentation for
 * select on how to do this (Hint: Iterate with FD_ISSET()).
 */

#include <assert.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <glib.h>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


/* This can be used to build instances of GTree that index on
   the address of a connection. */
int sockaddr_in_cmp(const void *addr1, const void *addr2)
{
	const struct sockaddr_in *_addr1 = addr1;
	const struct sockaddr_in *_addr2 = addr2;

	/* If either of the pointers is NULL or the addresses
	   belong to different families, we abort. */
	g_assert((_addr1 == NULL) || (_addr2 == NULL) ||
	     (_addr1->sin_family != _addr2->sin_family));

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



int main(int argc, char **argv)
{
	int sockfd;
	struct sockaddr_in server, client;
	SSL_CTX *ssl_ctx;
	SSL *server_ssl;
	const SSL_METHOD *meth;

	/* Initialize OpenSSL */
	SSL_library_init();
	SSL_load_error_strings();

    /*Create SSL_METHOD*/
    meth = SSLv3_method();

    // TLS fyrir skil
    /*Create SSL_CTX*/
    ssl_ctx = SSL_CTX_new(meth);

    if(ssl_ctx == NULL) {
        printf("The context is null\n");
        exit(1);
    }

    printf("Setting up the certificate and private key\n");
    /*Setting up the certificate and private key*/
    SSL_CTX_use_certificate_file(ssl_ctx, "fd.crt", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ssl_ctx, "fd.key", SSL_FILETYPE_PEM);
    /*Checking if client certificate and the private key matches*/
    SSL_CTX_check_private_key(ssl_ctx);

	/* Create and bind a TCP socket */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	/* Network functions need arguments in network byte order instead of
	   host byte order. The macros htonl, htons convert the values, */
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(9965);
	bind(sockfd, (struct sockaddr *) &server, (socklen_t) sizeof(server));

	/* Before we can accept messages, we have to listen to the port. We allow one
	 * 1 connection to queue for simplicity.
	 */
	listen(sockfd, 1);

    printf("listen done\n");


	for (;;) {
        fd_set rfds;
        struct timeval tv;
        int retval;

        /* Check whether there is data on the socket fd. */
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);

        /* Wait for five seconds. */
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        retval = select(sockfd + 1, &rfds, NULL, NULL, &tv);

        if (retval == -1) {
            perror("select()");
        } else if (retval > 0) {
            /* Data is available, receive it. */
            assert(FD_ISSET(sockfd, &rfds));
            printf("data available\n");
            /* Copy to len, since recvfrom may change it. */
            socklen_t len = (socklen_t) sizeof(client);

            /* For TCP connectios, we first have to accept. */
            int connfd;
            connfd = accept(sockfd, (struct sockaddr *) &client,
                            &len);

            server_ssl = SSL_new(ssl_ctx);
            SSL_set_accept_state(server_ssl);
            SSL_set_fd(server_ssl, sockfd);
            SSL_accept(server_ssl);

            /* Receive one byte less than declared,
               because it will be zero-termianted
               below.*/ 
            //ssize_t n = read(connfd, message, sizeof(message) - 1);
            
            /* Send the message back. */
            write(connfd, "Whalecum", strlen("Whalecum"));

            /* We should close the connection. */
            shutdown(connfd, SHUT_RDWR);
            close(connfd);
        } else {
            fprintf(stdout, "No message in five seconds.\n");
            fflush(stdout);
        }
	}
}
