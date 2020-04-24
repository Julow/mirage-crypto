
open Stdlib.Bigarray

let buffer = Array1.create char c_layout


type buffer = (char, int8_unsigned_elt, c_layout) Array1.t

type off    = int
type size   = int
type secret = buffer
type key    = buffer
type ctx    = bytes


let _cpu_supports flag =
  match Cpuid.supports [flag] with
  | Ok r -> r
  | Error _ -> false

module type AES = sig
  val enc      : buffer -> off -> buffer -> off -> key -> int -> size -> unit
  val dec      : buffer -> off -> buffer -> off -> key -> int -> size -> unit
  val derive_e : secret -> off -> key -> int -> unit
  val derive_d : secret -> off -> key -> int -> key option -> unit
  val rk_s     : int  -> int
  val mode     : unit -> int
end

module AES : AES = struct

  module AES_generic = struct
    external enc      : buffer -> off -> buffer -> off -> key -> int -> size -> unit = "mc_aes_enc_generic_bc" "mc_aes_enc_generic" [@@noalloc]
    external dec      : buffer -> off -> buffer -> off -> key -> int -> size -> unit = "mc_aes_dec_generic_bc" "mc_aes_dec_generic" [@@noalloc]
    external derive_e : secret -> off -> key -> int -> unit = "mc_aes_derive_e_key_generic" [@@noalloc]
    external derive_d : secret -> off -> key -> int -> key option -> unit = "mc_aes_derive_d_key_generic" [@@noalloc]
    external rk_s     : int  -> int = "mc_aes_rk_size_generic" [@@noalloc]
    let mode () = 0
  end

  module AES_aesni = struct
    external enc      : buffer -> off -> buffer -> off -> key -> int -> size -> unit = "mc_aes_enc_aesni_bc" "mc_aes_enc_aesni" [@@noalloc]
    external dec      : buffer -> off -> buffer -> off -> key -> int -> size -> unit = "mc_aes_dec_aesni_bc" "mc_aes_dec_aesni" [@@noalloc]
    external derive_e : secret -> off -> key -> int -> unit = "mc_aes_derive_e_key_aesni" [@@noalloc]
    external derive_d : secret -> off -> key -> int -> key option -> unit = "mc_aes_derive_d_key_aesni" [@@noalloc]
    external rk_s     : int  -> int = "mc_aes_rk_size_aesni" [@@noalloc]
    external mode     : unit -> int = "mc_aes_mode_aesni" [@@noalloc]
  end

  let aesni_supported = _cpu_supports `AES
  let aesni_enabled = AES_aesni.mode () = 1

  let impl =
    if aesni_supported && aesni_enabled
    then (module AES_aesni : AES)
    else (module AES_generic : AES)

  include (val impl)

end

module DES = struct
  external ddes    : buffer -> off -> buffer -> off -> int -> unit = "mc_des_ddes" [@@noalloc]
  external des3key : secret -> off -> int -> unit = "mc_des_des3key" [@@noalloc]
  external cp3key  : key -> unit = "mc_des_cp3key" [@@noalloc]
  external use3key : key -> unit = "mc_des_use3key" [@@noalloc]
  external k_s     : unit -> int = "mc_des_key_size" [@@noalloc]
end

module MD5 = struct
  external init     : ctx -> unit = "mc_md5_init" [@@noalloc]
  external update   : ctx -> buffer -> off -> size -> unit = "mc_md5_update" [@@noalloc]
  external finalize : ctx -> buffer -> off -> unit = "mc_md5_finalize" [@@noalloc]
  external ctx_size : unit -> int = "mc_md5_ctx_size" [@@noalloc]
end

module SHA1 = struct
  external init     : ctx -> unit = "mc_sha1_init" [@@noalloc]
  external update   : ctx -> buffer -> off -> size -> unit = "mc_sha1_update" [@@noalloc]
  external finalize : ctx -> buffer -> off -> unit = "mc_sha1_finalize" [@@noalloc]
  external ctx_size : unit -> int = "mc_sha1_ctx_size" [@@noalloc]
end

module SHA224 = struct
  external init     : ctx -> unit = "mc_sha224_init" [@@noalloc]
  external update   : ctx -> buffer -> off -> size -> unit = "mc_sha224_update" [@@noalloc]
  external finalize : ctx -> buffer -> off -> unit = "mc_sha224_finalize" [@@noalloc]
  external ctx_size : unit -> int = "mc_sha224_ctx_size" [@@noalloc]
end

module SHA256 = struct
  external init     : ctx -> unit = "mc_sha256_init" [@@noalloc]
  external update   : ctx -> buffer -> off -> size -> unit = "mc_sha256_update" [@@noalloc]
  external finalize : ctx -> buffer -> off -> unit = "mc_sha256_finalize" [@@noalloc]
  external ctx_size : unit -> int = "mc_sha256_ctx_size" [@@noalloc]
end

module SHA384 = struct
  external init     : ctx -> unit = "mc_sha384_init" [@@noalloc]
  external update   : ctx -> buffer -> off -> size -> unit = "mc_sha384_update" [@@noalloc]
  external finalize : ctx -> buffer -> off -> unit = "mc_sha384_finalize" [@@noalloc]
  external ctx_size : unit -> int = "mc_sha384_ctx_size" [@@noalloc]
end

module SHA512 = struct
  external init     : ctx -> unit = "mc_sha512_init" [@@noalloc]
  external update   : ctx -> buffer -> off -> size -> unit = "mc_sha512_update" [@@noalloc]
  external finalize : ctx -> buffer -> off -> unit = "mc_sha512_finalize" [@@noalloc]
  external ctx_size : unit -> int = "mc_sha512_ctx_size" [@@noalloc]
end

module type GHASH = sig
  val keysize : unit -> int
  val keyinit : buffer -> off -> bytes -> unit
  val ghash : bytes -> bytes -> buffer -> off -> size -> unit
  val mode : unit -> int
end

module GHASH = struct

  module GHASH_generic = struct
    external keysize : unit -> int = "mc_ghash_key_size_generic" [@@noalloc]
    external keyinit : buffer -> off -> bytes -> unit = "mc_ghash_init_key_generic" [@@noalloc]
    external ghash : bytes -> bytes -> buffer -> off -> size -> unit = "mc_ghash_generic" [@@noalloc]
    let mode () = 0
  end

  module GHASH_pclmul = struct
    external keysize : unit -> int = "mc_ghash_key_size_pclmul" [@@noalloc]
    external keyinit : buffer -> off -> bytes -> unit = "mc_ghash_init_key_pclmul" [@@noalloc]
    external ghash : bytes -> bytes -> buffer -> off -> size -> unit = "mc_ghash_pclmul" [@@noalloc]
    external mode : unit -> int = "mc_ghash_mode_pclmul" [@@noalloc]
  end

  let pclmul_supported = _cpu_supports `PCLMULQDQ
  let pclmul_enabled = GHASH_pclmul.mode () = 1

  let impl =
    if pclmul_supported && pclmul_enabled
    then (module GHASH_pclmul : GHASH)
    else (module GHASH_generic : GHASH)

  include (val impl)

end

module type MISC = sig
  val xor_into : buffer -> off -> buffer -> off -> size -> unit
  val count16be4 : bytes -> buffer -> off -> blocks:size -> unit
  external count8be   : bytes -> buffer -> off -> blocks:size -> unit = "mc_count_8_be"    [@@noalloc]
  external count16be  : bytes -> buffer -> off -> blocks:size -> unit = "mc_count_16_be"   [@@noalloc]
  external blit : buffer -> off -> buffer -> off -> size -> unit = "caml_blit_bigstring_to_bigstring" [@@noalloc]
  val mode : unit -> int
end

module Misc : MISC = struct

  module Misc_generic = struct
    (* XXX TODO
     * Unsolved: bounds-checked XORs are slowing things down considerably... *)
    external xor_into : buffer -> off -> buffer -> off -> size -> unit = "mc_xor_into_generic" [@@noalloc]

    external count8be   : bytes -> buffer -> off -> blocks:size -> unit = "mc_count_8_be"    [@@noalloc]
    external count16be  : bytes -> buffer -> off -> blocks:size -> unit = "mc_count_16_be"   [@@noalloc]
    external count16be4 : bytes -> buffer -> off -> blocks:size -> unit = "mc_count_16_be_4_generic" [@@noalloc]

    external blit : buffer -> off -> buffer -> off -> size -> unit = "caml_blit_bigstring_to_bigstring" [@@noalloc]
    let mode () = 0
  end

  module Misc_sse = struct
    external xor_into : buffer -> off -> buffer -> off -> size -> unit = "mc_xor_into_sse" [@@noalloc]
    external count16be4 : bytes -> buffer -> off -> blocks:size -> unit = "mc_count_16_be_4_sse" [@@noalloc]
    external mode : unit -> int = "mc_misc_mode_sse" [@@noalloc]

    (* Same as Misc_generic *)
    external count8be   : bytes -> buffer -> off -> blocks:size -> unit = "mc_count_8_be"    [@@noalloc]
    external count16be  : bytes -> buffer -> off -> blocks:size -> unit = "mc_count_16_be"   [@@noalloc]
    external blit : buffer -> off -> buffer -> off -> size -> unit = "caml_blit_bigstring_to_bigstring" [@@noalloc]
  end

  let sse_supported = _cpu_supports `SSSE3
  let sse_enabled = Misc_sse.mode () = 1

  let impl =
    if sse_supported && sse_enabled
    then (module Misc_sse : MISC)
    else (module Misc_generic : MISC)

  include (val impl)

end

include Misc
