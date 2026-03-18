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

#define W 8 // GF(2^8)
#define DATA_SIZE (10 * 1024 * 1024) // 10 MB base payload

// --- TIMING HELPER ---
double get_time_diff(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
}

// --- SERVER/DISK EMULATION ---
void emulate_storage_nodes(char **data_ptrs, char **coding_ptrs, int k, int m, int block_size) {
    char path[256];
    for (int i = 0; i < k; i++) {
        sprintf(path, "/tmp/node_data_%d", i);
        mkdir(path, 0777); 
        sprintf(path, "/tmp/node_data_%d/slice.dat", i);
        FILE *fp = fopen(path, "wb");
        if (fp) { fwrite(data_ptrs[i], 1, block_size, fp); fclose(fp); }
    }
    for (int i = 0; i < m; i++) {
        sprintf(path, "/tmp/node_coding_%d", i);
        mkdir(path, 0777); 
        sprintf(path, "/tmp/node_coding_%d/slice.dat", i);
        FILE *fp = fopen(path, "wb");
        if (fp) { fwrite(coding_ptrs[i], 1, block_size, fp); fclose(fp); }
    }
}

// [Keep your existing aont_fast and aont_secure functions exactly as they are here]
// ... 

// --- ISOLATED BENCHMARK FUNCTION ---
void run_benchmark(int k, int n, double *results) {
    int m = n - k;
    
    unsigned char *original_data;
    posix_memalign((void**)&original_data, 64, DATA_SIZE);
    RAND_bytes(original_data, DATA_SIZE);

    int padded_size = DATA_SIZE + 32; 
    int block_size = padded_size / k;
    if (padded_size % k != 0) block_size++; 
    
    // Strict AVX/SSE Alignment
    if (block_size % 64 != 0) {
        block_size += 64 - (block_size % 64);
    }
    padded_size = block_size * k; 

    unsigned char *pkg_buffer;
    posix_memalign((void**)&pkg_buffer, 64, padded_size);
    memset(pkg_buffer, 0, padded_size);

    char **data_ptrs = malloc(k * sizeof(char*));
    char **coding_ptrs = malloc(n * sizeof(char*)); 
    for(int i=0; i<n; i++) {
        posix_memalign((void**)&coding_ptrs[i], 64, block_size);
    }

    struct timespec start, end;
    double time_taken;
    int *matrix;

    // 1. Shamir
    for(int i=0; i<k; i++) data_ptrs[i] = (char*)original_data + i * (DATA_SIZE / k);
    matrix = reed_sol_vandermonde_coding_matrix(k, n, W); 
    clock_gettime(CLOCK_MONOTONIC, &start);
    jerasure_matrix_encode(k, n, W, matrix, data_ptrs, coding_ptrs, DATA_SIZE / k);
    emulate_storage_nodes(data_ptrs, coding_ptrs, k, n, DATA_SIZE / k); // M is N for Shamir simulation
    clock_gettime(CLOCK_MONOTONIC, &end);
    results[0] = (DATA_SIZE / 1048576.0) / get_time_diff(start, end);
    free(matrix);

    // 2. Rabin
    matrix = reed_sol_vandermonde_coding_matrix(k, m, W);
    clock_gettime(CLOCK_MONOTONIC, &start);
    jerasure_matrix_encode(k, m, W, matrix, data_ptrs, coding_ptrs, DATA_SIZE / k);
    emulate_storage_nodes(data_ptrs, coding_ptrs, k, m, DATA_SIZE / k);
    clock_gettime(CLOCK_MONOTONIC, &end);
    results[1] = (DATA_SIZE / 1048576.0) / get_time_diff(start, end);

    // 3. AONT-RS Fast
    clock_gettime(CLOCK_MONOTONIC, &start);
    // [Insert your aont_fast call here]
    for(int i=0; i<k; i++) data_ptrs[i] = (char*)pkg_buffer + i * block_size;
    jerasure_matrix_encode(k, m, W, matrix, data_ptrs, coding_ptrs, block_size);
    emulate_storage_nodes(data_ptrs, coding_ptrs, k, m, block_size);
    clock_gettime(CLOCK_MONOTONIC, &end);
    results[2] = (DATA_SIZE / 1048576.0) / get_time_diff(start, end);

    // 4. AONT-RS Secure
    memset(pkg_buffer, 0, padded_size);
    clock_gettime(CLOCK_MONOTONIC, &start);
    // [Insert your aont_secure call here]
    for(int i=0; i<k; i++) data_ptrs[i] = (char*)pkg_buffer + i * block_size;
    jerasure_matrix_encode(k, m, W, matrix, data_ptrs, coding_ptrs, block_size);
    emulate_storage_nodes(data_ptrs, coding_ptrs, k, m, block_size);
    clock_gettime(CLOCK_MONOTONIC, &end);
    results[3] = (DATA_SIZE / 1048576.0) / get_time_diff(start, end);

    // Cleanup for next iteration
    free(matrix);
    free(original_data);
    free(pkg_buffer);
    free(data_ptrs);
    for(int i=0; i<n; i++) free(coding_ptrs[i]);
    free(coding_ptrs);
}

int main() {
    // Define the ratios matching the paper's 5 graphs
    double ratios[] = {1.0/6.0, 1.0/3.0, 1.0/2.0, 2.0/3.0, 5.0/6.0};
    char* ratio_labels[] = {"1/6", "1/3", "1/2", "2/3", "5/6"};
    
    // Print CSV Header
    printf("Ratio_Label,Ratio_Val,N,K,Shamir_MBs,Rabin_MBs,AONT_Fast_MBs,AONT_Secure_MBs\n");

    // Outer Loop: The 5 graphs
    for (int r = 0; r < 5; r++) {
        double current_ratio = ratios[r];
        
        // Inner Loop: Sweep N from 6 to 36
        for (int n = 6; n <= 36; n += 6) {
            
            // Calculate K dynamically based on target ratio
            int k = (int)(n * current_ratio);
            if (k < 1) k = 1; // Safeguard
            
            // Don't run if K >= N (Invalid erasure code state)
            if (k >= n) continue;

            double results[4] = {0};
            
            // Execute the heavily-aligned benchmark suite
            run_benchmark(k, n, results);
            
            // Output CSV row
            printf("%s,%f,%d,%d,%.2f,%.2f,%.2f,%.2f\n", 
                   ratio_labels[r], current_ratio, n, k, 
                   results[0], results[1], results[2], results[3]);
        }
    }
    return 0;
}