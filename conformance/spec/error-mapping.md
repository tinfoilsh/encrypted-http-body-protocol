# Native Error -> Canonical Code

Adapters do not translate errors. Each SDK attaches the canonical code to its own
error (SPEC 5.5, `errors.md` "Exposure in SDKs"), and every adapter's `map_error`
is a single read of that code, falling back to `INVALID_INPUT` only for an error
the library left uncoded (a transport failure or an adapter-side input error).

The mapping from failure condition to code is therefore defined once, in each
library's raise sites, and audited by the fixtures: a mis-assigned code shows up
as a divergence in the report, not as a silent remap here.

Behavioral divergences (a library accepting input it should reject, or rejecting
with the wrong code) are tracked as issues and listed in the generated
`report.md`; they are not recorded in this file.
