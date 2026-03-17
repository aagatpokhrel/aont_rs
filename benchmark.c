#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

// Jerasure headers
#include <jerasure.h>
#include <reed_sol.h>

#define W 8 // GF(2^8) as used in the paper
#define K 10 // 10 data slices
#define M 6  // 6 coding slices (N = 16)
#define N (K + M)

// 10 MB base data size so it divides perfectly by K=10 (1 MB per slice)
#define DATA_SIZE (10 * 1024 * 1024) 

// --- TIMING HELPER ---
double get_time_diff(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
}

// --- SERVER/DISK EMULATION ---
void emulate_storage_nodes(char **data_ptrs, char **coding_ptrs, int block_size) {
    char path[256];
    
    // Write Data Slices (First K nodes)
    for (int i = 0; i < K; i++) {
        sprintf(path, "/tmp/node_data_%d", i);
        mkdir(path, 0777); 
        sprintf(path, "/tmp/node_data_%d/slice.dat", i);
        FILE *fp = fopen(path, "wb");
        if (fp) { fwrite(data_ptrs[i], 1, block_size, fp); fclose(fp); }
    }

    // Write Coding Slices (Remaining M nodes)
    for (int i = 0; i < M; i++) {
        sprintf(path, "/tmp/node_coding_%d", i);
        mkdir(path, 0777); 
        sprintf(path, "/tmp/node_coding_%d/slice.dat", i);
        FILE *fp = fopen(path, "wb");
        if (fp) { fwrite(coding_ptrs[i], 1, block_size, fp); fclose(fp); }
    }
}

// --- AONT FAST (RC4-128 + MD5) ---
void aont_fast(unsigned char *data, size_t data_len, unsigned char *output_pkg) {
    unsigned char key[16];
    RAND_bytes(key, sizeof(key)); 

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_rc4(), NULL, key, NULL);
    int len;
    EVP_EncryptUpdate(ctx, output_pkg, &len, data, data_len);
    EVP_EncryptFinal_ex(ctx, output_pkg + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5(output_pkg, data_len, hash);

    unsigned char canary[16];
    for(int i = 0; i < 16; i++) canary[i] = hash[i] ^ key[i];
    memcpy(output_pkg + data_len, canary, 16);
}

// --- AONT SECURE (AES-256-CTR + SHA-256) ---
void aont_secure(unsigned char *data, size_t data_len, unsigned char *output_pkg) {
    unsigned char key[32], iv[16] = {0}; 
    RAND_bytes(key, sizeof(key)); 

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
    int len;
    EVP_EncryptUpdate(ctx, output_pkg, &len, data, data_len);
    EVP_EncryptFinal_ex(ctx, output_pkg + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(output_pkg, data_len, hash);

    unsigned char canary[32];
    for(int i = 0; i < 32; i++) canary[i] = hash[i] ^ key[i];
    memcpy(output_pkg + data_len, canary, 32);
}

int main() {
    printf("Initializing %d MB test payload (K=%d, N=%d)...\n\n", DATA_SIZE / (1024 * 1024), K, N);
    unsigned char *original_data = malloc(DATA_SIZE);
    RAND_bytes(original_data, DATA_SIZE);

    // Padding buffers slightly for AONT canaries
    int padded_size = DATA_SIZE + 32; 
    padded_size += K - (padded_size % K); // Ensure divisibility by K
    int block_size = padded_size / K;

    unsigned char *pkg_buffer = calloc(1, padded_size);

    // Setup Jerasure Pointers
    char **data_ptrs = malloc(K * sizeof(char*));
    char **coding_ptrs = malloc(N * sizeof(char*)); // N allocated to simulate Shamir
    for(int i=0; i<N; i++) coding_ptrs[i] = malloc(block_size);

    struct timespec start, end;
    double time_taken;
    int *matrix;

    // ---------------------------------------------------------
    // 1. Shamir's Secret Sharing (Simulated via Dense N x K Matrix)
    // ---------------------------------------------------------
    for(int i=0; i<K; i++) data_ptrs[i] = (char*)original_data + i * (DATA_SIZE / K);
    matrix = reed_sol_vandermonde_coding_matrix(K, N, W); 

    clock_gettime(CLOCK_MONOTONIC, &start);
    jerasure_matrix_encode(K, N, W, matrix, data_ptrs, coding_ptrs, DATA_SIZE / K);
    emulate_storage_nodes(data_ptrs, coding_ptrs, DATA_SIZE / K);
    clock_gettime(CLOCK_MONOTONIC, &end);

    time_taken = get_time_diff(start, end);
    printf("[1] Shamir's Method Total Throughput: %.2f MB/s\n", (DATA_SIZE / 1048576.0) / time_taken);
    free(matrix);

    // ---------------------------------------------------------
    // 2. Rabin's IDA (Systematic Reed-Solomon)
    // ---------------------------------------------------------
    matrix = reed_sol_vandermonde_coding_matrix(K, M, W);

    clock_gettime(CLOCK_MONOTONIC, &start);
    jerasure_matrix_encode(K, M, W, matrix, data_ptrs, coding_ptrs, DATA_SIZE / K);
    emulate_storage_nodes(data_ptrs, coding_ptrs, DATA_SIZE / K);
    clock_gettime(CLOCK_MONOTONIC, &end);

    time_taken = get_time_diff(start, end);
    printf("[2] Rabin's IDA Total Throughput:   %.2f MB/s\n", (DATA_SIZE / 1048576.0) / time_taken);

    // ---------------------------------------------------------
    // 3. AONT-RS Fast (RC4/MD5 + Systematic RS)
    // ---------------------------------------------------------
    clock_gettime(CLOCK_MONOTONIC, &start);
    aont_fast(original_data, DATA_SIZE, pkg_buffer);
    for(int i=0; i<K; i++) data_ptrs[i] = (char*)pkg_buffer + i * block_size;
    jerasure_matrix_encode(K, M, W, matrix, data_ptrs, coding_ptrs, block_size);
    emulate_storage_nodes(data_ptrs, coding_ptrs, block_size);
    clock_gettime(CLOCK_MONOTONIC, &end);

    time_taken = get_time_diff(start, end);
    printf("[3] AONT-RS Fast Total Throughput:  %.2f MB/s\n", (DATA_SIZE / 1048576.0) / time_taken);

    // ---------------------------------------------------------
    // 4. AONT-RS Secure (AES-256/SHA-256 + Systematic RS)
    // ---------------------------------------------------------
    memset(pkg_buffer, 0, padded_size);
    clock_gettime(CLOCK_MONOTONIC, &start);
    aont_secure(original_data, DATA_SIZE, pkg_buffer);
    for(int i=0; i<K; i++) data_ptrs[i] = (char*)pkg_buffer + i * block_size;
    jerasure_matrix_encode(K, M, W, matrix, data_ptrs, coding_ptrs, block_size);
    emulate_storage_nodes(data_ptrs, coding_ptrs, block_size);
    clock_gettime(CLOCK_MONOTONIC, &end);

    time_taken = get_time_diff(start, end);
    printf("[4] AONT-RS Secure Total Throughput:%.2f MB/s\n", (DATA_SIZE / 1048576.0) / time_taken);

    // Cleanup
    free(matrix);
    free(original_data);
    free(pkg_buffer);
    free(data_ptrs);
    for(int i=0; i<N; i++) free(coding_ptrs[i]);
    free(coding_ptrs);

    return 0;
}