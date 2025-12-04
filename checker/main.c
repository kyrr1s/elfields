#include "elfields.h"

int main() {
    if (check_elf_fields("57c8ad95177113e46a5b83718aac38b3101c493a")) {
        printf("Hello World\n");
    } else {
        printf("Integrity check failed\n");
        return 1;
    }
    
    return 0;
}