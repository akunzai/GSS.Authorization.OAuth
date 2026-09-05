# Credential placement stays two booleans per protocol

Each handler decides where the credential goes from two booleans — `SignedAsBody` /
`SignedAsQuery` for OAuth 1.0, `SendAccessTokenInBody` / `SendAccessTokenInQuery` for OAuth 2.0 —
tried in the order body, query, header. An architecture review proposed replacing them with a
three-value enum, and unifying the two protocols behind one placement module. We keep the booleans
and document the precedence on the properties instead.

## Considered Options

**A three-value enum.** The booleans are public API on published packages, so an enum can only be
added *beside* them, never replace them. Callers would then have to learn a third representation
plus how it interacts with the two booleans — the interface gets larger, not smaller, which is the
opposite of what the proposal was after. An enum that *replaces* the booleans belongs in a major
version.

**One placement module shared by both protocols.** The two are not the same operation. OAuth 2.0
puts a single value (`access_token`) in one of three locations. OAuth 1.0's choice decides which
parameters enter the signature base string: the body branch merges query parameters into the form
data, signs the merged set, and writes back only the non-query parameters. Sharing a module would
be a forced abstraction over two genuinely different procedures.
