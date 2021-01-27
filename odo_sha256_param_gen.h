//
// Created by cl on 2021/1/6.
//

#ifndef DIGIBYTE_ODO_SHA256_PARAM_H
#define DIGIBYTE_ODO_SHA256_PARAM_H

#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "bigint.h"
#include "odo_sha256_param_gen.h"
void generate(uint64_t key, uint32_t h256_out[8], uint32_t k256_out[64]);
#endif //DIGIBYTE_ODO_SHA256_PARAM_H
