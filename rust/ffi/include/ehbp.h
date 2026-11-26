/* C ABI over the verified EHBP event core (dafny/ehbp_events.dfy).
 * Hand-written; the value encoding is documented in conformance/spec/swift-ffi.md.
 * Every buffer returned through an out pointer is allocated by Rust and
 * released with ehbp_free_buf. The state is opaque. */
#ifndef EHBP_H
#define EHBP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct EhbpState EhbpState;

/* A core State from an encoded constructor (0 Initial, 1 ResponseOnly); NULL on malformed input. */
EhbpState *ehbp_state_new(const uint8_t *in, size_t in_len);
void ehbp_state_free(EhbpState *state);

/* Step(state, event): replaces the state and returns the encoded action list.
 * 0 ok; 1 malformed input; -1 the core panicked. */
int32_t ehbp_step(EhbpState *state, const uint8_t *event, size_t event_len, uint8_t **out, size_t *out_len);

/* KeysOf(state): encoded Option<(bytes, bytes)>. */
int32_t ehbp_keys_of(const EhbpState *state, uint8_t **out, size_t *out_len);

/* One pure core function by op number (swift-ffi.md), encoded arguments in, encoded result out.
 * 0 ok; 1 malformed input; 2 unknown op; -1 the core panicked. */
int32_t ehbp_call(uint32_t op, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len);

void ehbp_free_buf(uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif
