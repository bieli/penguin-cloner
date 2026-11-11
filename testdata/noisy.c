#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
volatile unsigned long real_counter;
int main(void) {
    void *keep[64] = {0};
    unsigned seed = 1;
    for (;;) {
        real_counter += 7;
        for (int k = 0; k < 400; k++) {            /* heavy allocator churn + random writes */
            seed = seed * 1103515245u + 12345u;
            int slot = seed % 64; free(keep[slot]);
            size_t n = 16 + (seed >> 8) % 2048; keep[slot] = malloc(n);
            for (size_t j = 0; j < n; j += 8) { seed = seed * 1103515245u + 12345u; ((unsigned *)keep[slot])[j / 4] = seed; }
        }
        char junk[512]; for (int j = 0; j < 512; j++) junk[j] = rand();   /* stack noise */
        __asm__ volatile("" :: "r"(junk) : "memory");
        usleep(50000);
    }
}
