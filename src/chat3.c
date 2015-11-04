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

/* For nicer interaction, we use the GNU readline library. */
#include <readline/readline.h>
#include <readline/history.h>

#define RETURN_NULL(x)    if ((x)==NULL) exit (1)
#define RETURN_ERR(err,s) if ((err)==-1) { perror(s); return 0; }
#define RETURN_SSL(err)   if ((err)==-1) { ERR_print_errors_fp(stderr); return 0; }
 
#define RSA_CLIENT_CERT         "fd.crt"
#define RSA_CLIENT_KEY          "fd.key"
 
#define ON      1
#define OFF     0

static int active = 1; 

/* This variable shall point to the name of the user. The initial value
   is NULL. Set this variable to the username once the user managed to be
   authenticated. */
static char *user;

/* This variable shall point to the name of the chatroom. The initial
   value is NULL (not member of a chat room). Set this variable whenever
   the user changed the chat room successfully. */
static char *chatroom;

/* This prompt is used by the readline library to ask the user for
 * input. It is good style to indicate the name of the user and the
 * chat room he is in as part of the prompt. */
static char *prompt;

void readline_callback(char *line)
{
    char buffer[256];
    if (line == NULL) {
        rl_callback_handler_remove();
        active = 0;
        return;
    }
    if (strlen(line) > 0) {
        add_history(line);
    }
    if ((strncmp("/bye", line, 4) == 0) ||
        (strncmp("/quit", line, 5) == 0)) {
        rl_callback_handler_remove();
        active = 0;
        return;
    }
    if (strncmp("/game", line, 5) == 0) {
        /* Skip whitespace */
        int i = 4;
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /game username\n", 29);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }
        /* Start game */
        return;
    }
    if (strncmp("/join", line, 5) == 0) {
        int i = 5;
        /* Skip whitespace */
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /join chatroom\n", 22);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }
        char *chatroom = strdup(&(line[i]));
        printf("chatroom: %s\n", chatroom);
        /* Process and send this information to the server. */

        /* Maybe update the prompt. */
        free(prompt);
        prompt = NULL; /* What should the new prompt look like? -- username and chatroom*/
		rl_set_prompt(prompt);
        return;
    }
    if (strncmp("/list", line, 5) == 0) {
        /* Query all available chat rooms */
        return;
    }
    if (strncmp("/roll", line, 5) == 0) {
        /* roll dice and declare winner. */
        return;
    }
    if (strncmp("/say", line, 4) == 0) {
		/* Skip whitespace */
		int i = 4;
		while (line[i] != '\0' && isspace(line[i])) { i++; }
		if (line[i] == '\0') {
			write(STDOUT_FILENO, "Usage: /say username message\n", 29);
			fsync(STDOUT_FILENO);
			rl_redisplay();
		    return;
		}
		/* Skip whitespace */
		int j = i+1;
		while (line[j] != '\0' && isgraph(line[j])) { j++; }
		if (line[j] == '\0') {
	        write(STDOUT_FILENO, "Usage: /say username message\n", 29);
	        fsync(STDOUT_FILENO);
	        rl_redisplay();
	        return;
		}
		char *receiver = strndup(&(line[i]), j - i - 1);
		char *message = strndup(&(line[j]), j - i - 1);
		printf("receiver: %s \n message: %s \n", receiver, message);

		/* Send private message to receiver. */

		return;
    }
    if (strncmp("/user", line, 5) == 0) {
		int i = 5;
		/* Skip whitespace */
		while (line[i] != '\0' && isspace(line[i])) { i++; }
		if (line[i] == '\0') {
			write(STDOUT_FILENO, "Usage: /user username\n", 22);
			fsync(STDOUT_FILENO);
			rl_redisplay();
			return;
		}
		char *new_user = strdup(&(line[i]));
		printf("new_user: %s \n", new_user);
		char passwd[48];
		//getpasswd("Password: ", passwd, 48);

		/* Process and send this information to the server. */

		/* Maybe update the prompt. */
		free(prompt);
		prompt = NULL; /* What should the new prompt look like? -- username?*/
		rl_set_prompt(prompt);
		return;
    }
    if (strncmp("/who", line, 4) == 0) {
		/* Query all available users */
		return;
    }
    /* Sent the buffer to the server. */
    snprintf(buffer, 255, "Message: %s\n", line);
    write(STDOUT_FILENO, buffer, strlen(buffer));
    fsync(STDOUT_FILENO);
}

void checkIfBye(char* message) {
	if ((strncmp("/bye", message, 4) == 0) ||
        (strncmp("/quit", message, 5) == 0)) {
		printf("bye sent!\n");
        active = 0;
        return;
    }
}

void sigint_handler(int signum)
{
	printf("signum: %d", signum);
    active = 0;
    /* We should not use printf inside of signal handlers, this is not
     * considered safe. We may, however, use write() and fsync(). */
    write(STDOUT_FILENO, "Terminated.\n", 12);
    fsync(STDOUT_FILENO);
}

int main() {
	int             err;
	int             sock;
	struct          sockaddr_in server_addr;
	char            buf [4096];
	//char            message[1204];

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
 	prompt = strdup("> ");
    rl_callback_handler_install(prompt, (rl_vcpfunc_t*) &readline_callback);
    while (active) {
    	fd_set rfds;
		struct timeval timeout;

        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
 	  
		int r = select(STDIN_FILENO + 1, &rfds, NULL, NULL, &timeout);
        if (r < 0) {
        	if (errno == EINTR) {
            	/* This should either retry the call or
                   exit the loop, depending on whether we
                   received a SIGTERM. */
                continue;
            }
            /* Not interrupted, maybe nothing we can do? */
            perror("select()");
            break;
        }
        if (r == 0) {
        	SSL_write(ssl, STDOUT_FILENO, strlen(STDOUT_FILENO));
        	fsync(STDOUT_FILENO);
            /* Whenever you print out a message, call this
               to reprint the current input line. */
			rl_redisplay();
            continue;
        }
        if (FD_ISSET(STDIN_FILENO, &rfds)) {
        	rl_callback_read_char();
        }
        /* Handle messages from the server here! */

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