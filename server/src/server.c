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
#define RSA_KEY_BITS (4096)

#define PORT 8000

#define REQ_DN_C "US"
#define REQ_DN_ST "MI"
#define REQ_DN_L ""
#define REQ_DN_O "Grand Valley State University"
#define REQ_DN_OU "IT"
#define REQ_DN_CN "www.gvsu.edu"

#define RETURN_NULL(x) if ((x) == NULL) exit(1)
#define RETURN_ERR(err, s) if ((err) == -1) { perror(s); exit(1); }
#define RETURN_SSL(err) if ((err) == -1) { ERR_print_errors_fp(stderr); exit(1); }

static void cleanup(void);
static void cty_to_pem(X509 *crt, uint8_t **crt_bytes, size_t *crt_size);
static int generate_key_csr(EVP_PKEY **key, X509_REQ **req);
static int generate_set_random_serial(X509 *crt);
static int generate_signed_key_pair(EVP_PKEY *ca_key, X509 *ca_crt, EVP_PKEY **key, X509 **crt);
static void initialize(void);
static void key_to_pem(EVP_PKEY *key, uint8_t **key_bytes, size_t *key_size);
static int load_ca(const char *ca_key_path, EVP_PKEY **ca_key, const char *ca_crt_path, X509 **ca_crt);
static void print_bytes(uint8_t *data, size_t size);
static int server_loop(int port);

/**
 * Initializes the openssl functions
 *
 * @return void
 */
void initialize() {
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
}

/**
 * Clean up the openssl functions.
 * 
 * @return void
 */
void cleanup(){
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	ERR_remove_thread_state(NULL);
}	

/**
 * This code converts an X509 cert to PEM format
 *
 * @return void
 */
void crt_to_pem(X509 *crt, uint8_t **crt_bytes, size_t *crt_size) {
	/* Set up a bio to store the PEM data */
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio, crt);
	/* Get the size of the certification */
	/* This functions similar to strlen */
	*crt_size = BIO_pending(bio); 
	*crt_bytes = (uint8_t *)malloc(*crt_size + 1);
	/* Read the cert into pem format */
	BIO_read(bio, *crt_bytes, *crt_size);
	/* Free the BIO memory */
	BIO_free_all(bio);
}

/**
 * This code converts an RSA private key to PEM format
 *
 * @return void
 */
void key_to_pem(EVP_PKEY* key, uint8_t** key_bytes, size_t* key_size) {
	/* Set up bio to store the private key */
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
	/* Get the private key size from the bio */
	*key_size = BIO_pending(bio);
	*key_bytes = (uint8_t*)malloc(*key_size + 1);
	/* Read the data into the bio */
	BIO_read(bio, *key_bytes, *key_size);
	BIO_free_all(bio);	
}

/**
 * Loads the CA system to validate certificates
 *
 * @return int
 */
int load_ca(const char* ca_key_path, EVP_PKEY **ca_key, const char* ca_crt_path, X509 **ca_crt) {
	BIO *bio = NULL;
	*ca_crt = NULL;
	*ca_key = NULL;

	/* Load the CA public key into a bio */
	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, ca_crt_path)) goto err;
	*ca_crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (!*ca_crt) goto err;
	BIO_free_all(bio);

	/* Load the CA private key into a bio */
	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, ca_key_path)) goto err;
	*ca_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if (!ca_key) goto err;
	BIO_free_all(bio);
	return 1;

/* Jump Desination for error handling */
err:
	/* Free bio data structures */
	BIO_free_all(bio);
	/* Free X509 data structures */
	X509_free(*ca_crt);
	/* Free Envelope private key data structures */
	EVP_PKEY_free(*ca_key);
	return 0;
}

void print_bytes(uint8_t* data, size_t size) {
	for (size_t i = 0; i < size; i++) {
		printf("%s", data[i]);
	}
}

int main(int argc, char **argv) {
	/** Load CA key and cert */
	initialize();

}
