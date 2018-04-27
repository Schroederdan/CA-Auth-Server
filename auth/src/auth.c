/**
 * Copyright 2018-present, Grand Valley State University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdio.h>
#include <stdlib.h>

#include <openssl/crypto.h> // Crypto lib
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h> // The crypto algorithm
#include <openssl/pem.h> // The public cert format

#define RSA_KEY_BITS (4096)

/* These will later need to be sent via the requesting server */
#define REQ_DN_C "US"
#define REQ_DN_ST "MI"
#define REQ_DN_L ""
#define REQ_DN_O "Grand Valley State University"
#define REQ_DN_OU "IT"
#define REQ_DN_CN "www.gvsu.edu"

static void cleanup(void);
static void cty_to_pem(X509 *crt, uint8_t **crt_bytes, size_t *crt_size);
static int generate_key_csr(EVP_PKEY **key, X509_REQ **req);
static int generate_set_random_serial(X509 *crt);
static int generate_signed_key_pair(EVP_PKEY *ca_key, X509 *ca_crt, EVP_PKEY **key, X509 **crt);
static void initialize(void);
static void key_to_pem(EVP_PKEY *key, uint8_t **key_bytes, size_t *key_size);
static int load_ca(const char *ca_key_path, EVP_PKEY **ca_key, const char *ca_crt_path, X509 **ca_crt);
static void print_bytes(uint8_t *data, size_t size);

/**
 * Generates a new 20-byte random serial number
 *
 * This 20-byte value will be able to uniquely
 * identify the certificate when issued by the
 * CA server.
 *
 * This will be used to check and see if a certificate
 * for a given server requesting authentication
 * exists.
 */
int generate_set_random_serial(X509 *crt) {
	
}

/**
 * Creates a new Certificate Signing Request
 * Which allows for the creation of a new
 * certificate on the CA server. 
 *
 *
 * This will be referenced whenever the associated
 * server tries to connect to the organization's network.
 * It will allow for the CA to validate the certificate
 * against what is saved, and allow or deny access.
 *
 * @return int
 */ 
int generate_key_csr(EVP_PKEY **key, X509_REQ **req) {
	/* Allocate an empty EVP_PKEY structure inside of key */
	*key = EVP_PKEY_new();
	if (!*key) goto err;

	/* Generate X509 typed object inside of req */
	*req = X509_REQ_new();
	if (!*req) goto err;

	/* Generate the RSA key */
	RSA *rsa = RSA_generate_key(RSA_KEY_BITS, RSA_F4, NULL, NULL);
	if (!EVP_PKEY_assign_RSA(*key, rsa)) goto err;

	X509_REQ_set_pubkey(*req, *key);

	/* Set DN and other info for the CSA */
	X509_NAME *name = X509_REQ_get_subject_name(*req);
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)REQ_DN_C, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (const unsigned char*)REQ_DN_ST, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (const unsigned char*)REQ_DN_L, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)REQ_DN_O, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (const unsigned char*)REQ_DN_OU, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)REQ_DN_CN, -1, -1, 0);

	/* Self-sign the request to prove we have the key */
	if (!X509_REQ_sign(*req, *key, EVP_sha256())) goto err;
	return 1;

/* Error handler */
err:
	EVP_PKEY_free(*key);
	X509_REQ_free(*req);
	return 0;
}

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
/**
 * Prints the data into a byte stream
 */
void print_bytes(uint8_t* data, size_t size) {
	for (size_t i = 0; i < size; i++) {
		printf("%s", data[i]);
	}
}

int generate_signed_key_pair(EVP_PKEY *ca_key, X509 *ca_crt, EVP_PKEY **key, X509 **crt) {

	/* Generate the private key and corresponding CSR */
	X509_REQ *req = NULL;	
	if (!generate_key_csr(key, &req)) {
		fprintf(stderr, "Failed to generate key and/or csr!\n");
		return 0;	
	}

	/* Sign with the CA */
	*crt = X509_new();
	if (!*crt) goto err;

	/* Set version to X509v3 */
	X509_set_version(*crt, 2);
	

err:
	EVP_PKEY_free(*key);
	X509_REQ_free(*req);
	X509_free(*crt);
	return 0;
}

int main(int argc, char **argv) {
	/** Load CA key and cert */
	initialize();

}
