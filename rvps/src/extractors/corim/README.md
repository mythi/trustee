# CoRIM Extractor

This extractor parses CoRIM manifests and extracts reference values.

The CoRIM specification goes beyond simply specifying reference values, 
but our extractors are tightly tied to the internal RV representation
in the RVPS.

Thus, this extractor maps CoRIMs and the CoMIDs within to RV values
identified by URIs.

We use a flexible mechanism to map RVs in a CoRIM to RV URIs.
Specifically, any id-like fields found while parsing the manifest are
concatenated together with slashes to produce the reference values URI.

This extractor currently only supports a subset of CoRIM.
Only reference triples are supported and not all types of
identifiers are parsed.

The following identifiers will be added to the RV URI if they are present.
This list is in order, such that the first available identifier will be
the base of the URI. 

* Environment map vendor field
* Environment map model field
* MKey String, integer, or Uuid
* Mval name
* Mval serial number

If the mval is a list of digests, the string "digests" will be added to
the end of the URI, and the value will be a list of digests.

If the mval is raw bytes, the string "raw_bytes" will be added to the end
of the URI and the value will be the bytes converted to hex.

For example, an RV URI might look like:

* `ACME/RoadRunner/31fb5abf-023e-4992-aa4e-95f9c1503bfa/digests`
* `ACME/RoadRunner/31fb5abf-023e-4992-aa4e-95f9c1503bfa/raw_bytes`

## Intel Platform Ownership Endorsement (POE)

Intel's POE profile (`tag:intel.com,2026:tee.poe#1.0`, produced by
`poe-gen-tool`) doesn't use reference-triples at all. It binds a Platform
Instance ID (PIID) to an owner name via a conditional-endorsement triple: a
signed statement of the form "if the platform's PIID is X, its owner is Y".
This extractor recognizes that shape separately and produces one RV per
triple, named:

* `intel_poe/owner_name/<piid-hex>`

where `<piid-hex>` is the lowercase hex encoding of the PIID in its raw,
as-extracted byte order (matching Intel's own tooling, not a
byte-reversed/GUID-formatted form). The value is the owner name string.

Since this extractor doesn't verify CoRIM signatures (see below), it
accepts the to-be-signed CBOR directly, rather than requiring a fully
signed artifact: `poe-gen-tool derive-tbs`/`prepare`'s `poe.tbs.cbor`
output, a raw COSE `Sig_Structure`. There's no need to complete signing
just to register a POE endorsement here.

Note that, like the rest of this extractor, CoRIM signatures are not
verified before extraction -- for POE, or for any other profile that
submits a fully signed artifact instead.
