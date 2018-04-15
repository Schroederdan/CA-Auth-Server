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

#include <openssl/crypto.h> // Crypto lib
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h> // The crypto algorithm
#include <openssl/pem.h> // The public cert format

#define RSA_SERVER_CERT "server.crt"
#define RSA_SERVER_KEY  "server.key"
#define RSA_KEY_BITS 4096

#define RSA_SERVER_CA_CERT "server_ca.crt" // This will need to change when we generate keys properly.
#define RSA_SERVER_CA_PATH "sys$common:[auth.gvsu.ssl]" // This will need to change when we generate the keys properly.

#define ON  1
#define OFF 0

#define RETURN_NULL(x) if ((x) == NULL) exit(1)
#define RETURN_ERR(err, s) if ((err) == -1) { perror(s); exit(1); }
#define RETURN_SSL(err) if ((err) == -1) { ERR_print_errors_fp(stderr); exit(1); }

static void cleanup_crypto(void);
static void cty_to_pem(X509 *crt, uint8_t **crt_bytes, size_t *crt_size);
static int generate_key_csr(EVP_PKEY **key, X509_REQ **req);
static int generate_set_random_serial(X509 *crt);
static int generate_signed_key_pair(EVP_PKEY *ca_key, X509 *ca_crt, EVP_PKEY **key, X509 **crt);
static void initialize_crypto(void);
static void key_to_pem(EVP_PKEY *key, uint8_t **key_bytes, size_t *key_size);
static void load_ca(const char *ca_key_path, EVP_PKEY **ca_key, const char *ca_crt_path, X509 **ca_crt);
static int server_loop(int port);

int main(int argc, char **argv) {

}
