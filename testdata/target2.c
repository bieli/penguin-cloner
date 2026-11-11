#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>

/* config-like (rarely change) */
int max_connections = 512;
float ratio = 2.5f;
double timeout_sec = 3.0;
char server_name[32] = "legacy-01.example";
const char *config_path = "/etc/legacyd.conf";
/* runtime state (change while running) */
volatile unsigned long ticks;
volatile int requests;
volatile int busy;
volatile double load;
char status[16] = "idle";
struct session { unsigned long id; int hits; double score; char user[16]; } *sess;

int main(void) {
    sess = calloc(1, sizeof *sess);
    strcpy(sess->user, "alice");
    int i = 0;
    for (;;) {
        ticks += 1000;
        requests++;
        busy = !busy;
        load = 0.5 + 0.4 * sin(i * 0.3);
        sess->id = ticks;
        sess->hits += 3;
        sess->score = load * 2;
        strcpy(status, (i % 4 == 0) ? "idle" : "work");
        usleep(100000);
        i++;
        if (max_connections < 0 || ratio < 0 || timeout_sec < 0 || server_name[0] == 0 || config_path == 0) return 1;
    }
}
