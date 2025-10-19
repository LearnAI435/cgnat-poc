/**
 * CGNAT POC - Basic Carrier Grade NAT Simulation
 *
 * This is a simplified NAT implementation in C for educational purposes.
 * It simulates how multiple private IPs can share limited public IPs using
 * port-based mapping. (NOT production grade!)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SESSIONS 10000   // Max concurrent sessions
#define MAX_PUBLIC_IPS 10    // Number of public IP addresses available
#define MAX_PORTS_PER_IP 5000

typedef struct {
    char private_ip[16];
    int private_port;
    char public_ip[16];
    int public_port;
    int active;
} Session;

Session session_table[MAX_SESSIONS];
char public_ips[MAX_PUBLIC_IPS][16] = {
    "203.0.113.1",
    "203.0.113.2",
    "203.0.113.3",
    "203.0.113.4",
    "203.0.113.5",
    "203.0.113.6",
    "203.0.113.7",
    "203.0.113.8",
    "203.0.113.9",
    "203.0.113.10"
};

int next_ip_index = 0;
int next_port = 10000;  // starting port number for translation

/**
 * Get the next available public IP and port
 */
void allocate_public_ip_port(char *pub_ip, int *pub_port) {
    strcpy(pub_ip, public_ips[next_ip_index]);
    *pub_port = next_port;

    // Update for next allocation
    next_port++;
    if (next_port >= 10000 + MAX_PORTS_PER_IP) {
        next_port = 10000;
        next_ip_index = (next_ip_index + 1) % MAX_PUBLIC_IPS;
    }
}

/**
 * Create a NAT session entry
 */
void create_nat_session(const char *priv_ip, int priv_port) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!session_table[i].active) {
            strcpy(session_table[i].private_ip, priv_ip);
            session_table[i].private_port = priv_port;
            allocate_public_ip_port(session_table[i].public_ip, &session_table[i].public_port);
            session_table[i].active = 1;
            printf("[NEW SESSION] %s:%d -> %s:%d\n",
                   session_table[i].private_ip,
                   session_table[i].private_port,
                   session_table[i].public_ip,
                   session_table[i].public_port);
            return;
        }
    }
    printf("[ERROR] Session table full!\n");
}

/**
 * Translate a private IP:port to public IP:port
 */
void translate_packet(const char *priv_ip, int priv_port) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (session_table[i].active &&
            strcmp(session_table[i].private_ip, priv_ip) == 0 &&
            session_table[i].private_port == priv_port) {
            printf("[TRANSLATE] %s:%d -> %s:%d\n",
                   priv_ip, priv_port,
                   session_table[i].public_ip,
                   session_table[i].public_port);
            return;
        }
    }
    printf("[MISS] No active session, creating new one...\n");
    create_nat_session(priv_ip, priv_port);
}

/**
 * Show active session table
 */
void show_session_table() {
    printf("\n=== NAT SESSION TABLE ===\n");
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (session_table[i].active) {
            printf("%s:%d -> %s:%d\n",
                   session_table[i].private_ip,
                   session_table[i].private_port,
                   session_table[i].public_ip,
                   session_table[i].public_port);
        }
    }
    printf("=========================\n");
}

/**
 * Main
 */
int main() {
    memset(session_table, 0, sizeof(session_table));
    printf("=== CGNAT POC ===\n");

    // Simulate traffic from different customers
    translate_packet("10.0.0.1", 1234);
    translate_packet("10.0.0.2", 1235);
    translate_packet("10.0.0.3", 1236);
    translate_packet("10.0.0.1", 1234); // should reuse existing session

    // Bulk simulation
    for (int i = 0; i < 20; i++) {
        char priv_ip[16];
        sprintf(priv_ip, "10.0.0.%d", i + 10);
        translate_packet(priv_ip, 2000 + i);
    }

    show_session_table();

    return 0;
}
