#if !defined (H__MIRAGE_CRYPTO)
#define H__MIRAGE_CRYPTO

#include <stdint.h>
#include "bitfn.h"

#include <caml/mlvalues.h>
#include <caml/bigarray.h>

#if defined (__x86_64__) && defined (ACCELERATE)
#include <x86intrin.h>
#define __mc_ACCELERATE__
#endif

#ifndef __unused
#define __unused(x) x __attribute__((unused))
#endif
#define __unit() value __unused(_)

#define _ba_uint8_off(ba, off)  ((uint8_t*) Caml_ba_data_val (ba) + Long_val (off))
#define _ba_uint32_off(ba, off) ((uint32_t*) Caml_ba_data_val (ba) + Long_val (off))

#define _ba_uint8(ba)  ((uint8_t*) Caml_ba_data_val (ba))
#define _ba_uint32(ba) ((uint32_t*) Caml_ba_data_val (ba))

#define _bp_uint8_off(bp, off) ((uint8_t *) Bp_val (bp) + Long_val (off))
#define _bp_uint8(bp) ((uint8_t *) Bp_val (bp))
#define _bp_uint32(bp) ((uint32_t *) Bp_val (bp))

#define __define_bc_6(f) \
  CAMLprim value f ## _bc (value *v, int __unused(c) ) { return f(v[0], v[1], v[2], v[3], v[4], v[5]); }

#define __define_bc_7(f) \
  CAMLprim value f ## _bc (value *v, int __unused(c) ) { return f(v[0], v[1], v[2], v[3], v[4], v[5], v[6]); }

#endif /* H__MIRAGE_CRYPTO */
