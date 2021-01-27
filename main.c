#include <stdlib.h>
#include "bigint.h"
#include "sph_sha2.h"
#include "odo_sha256_param_gen.h"

int main(){
    uint64_t key = 1;
    uint32_t h256[8], k256[64];
    generate(key, h256, k256);

    sph_sha256_context state;
    sph_odo_sha256_init(&state, h256, k256);
    uint8_t data[8] = {2};
    sph_sha256(&state, data, 8);

    uint8_t out[32];
    sph_sha256_close(&state, out);
    int s = 1;
}

//#include <stdio.h>
//#include <stdlib.h>
//
//int values[] = { 88, 56, 100, 2, 25 };
//
//int cmpfunc (const void * a, const void * b)
//{
//    return ( *(int*)a - *(int*)b );
//}

//int main()
//{
//    int n;
//
//    printf("排序之前的列表：\n");
//    for( n = 0 ; n < 5; n++ ) {
//        printf("%d ", values[n]);
//    }
//
//    qsort(values, 5, sizeof(int), cmpfunc);
//
//    printf("\n排序之后的列表：\n");
//    for( n = 0 ; n < 5; n++ ) {
//        printf("%d ", values[n]);
//    }
//
//    return(0);
//}
