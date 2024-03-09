# ProfileFed

ProfileFed is a simple, lightweight federation protocol for platforms that host user profiles. This repository contains a reference implementation of the protocol, written in Go.

## Specification

### WebFinger

ProfileFed endpoints are discovered via [WebFinger](https://datatracker.ietf.org/doc/html/rfc7033). ProfileFed WebFinger responses must contain a link with a `rel` of `self` and a `type` of `application/x-pfd+json`. Requests to the URL contained within the `href` of that link must return a Profile Descriptor as defined below.

### Profile Descriptor (PFD)

This object represents a user profile returned by a ProfileFed server in response to a request to the ProfileFed URL discovered via WebFinger, as defined above.

This response must include a message signature. It should be transferred via the `X-ProfileFed-Sig` header, which must contain an Ed25519 signature of the response encoded in base64. The message must be verified against this signature before any further processing takes place. If the signature does not match, the response must be ignored and an error must be returned.

If the `all` query parameter is set to `1` in the request, the server must return all the profiles it has for the user, encoded as a JSON object with arbitrary ID strings mapped to profile descriptors. If the optional `id` query parameter is set to a specific descriptor ID, the server should respond with the corresponding profile. If no `id` is provided, the server may decide which profile to respond with.

The response should use the MIME type `application/x-pfd+json`.

**Profile Descriptor Object:**

| Property       | Type     | Description                                |
|----------------|----------|--------------------------------------------|
| `id`           | string   | Arbitrary ID string for the profile        |
| `namespaces`   | []string | List of namespaces used in the profile     |
| `display_name` | string   | User's preferred display name              |
| `username`     | string   | User's username                            |
| `bio`          | string   | User's bio text                            |
| `role`         | string   | User's role on the server                  |
| `extra`        | []extra  | Additional user data defined by namespaces |

If `role` is empty or not provided, `user` should be assumed

The `namespace` URLs should point to human-readable documentation of the types and data that can be used in the objects that they define.

Possible values for `role` are `server_host`, `admin`, `moderator`, `developer`, or `user`. The server can arbitrarily decide which roles apply to the user. If the user has multiple roles, they should be delimited by commas. If any other custom roles are required, they should be specified in `extra` and defined in a custom namespace.

**`extra` Object:**

| Property    | Type   | Description                               |
|-------------|--------|-------------------------------------------|
| `namespace` | string | The namespace URL used in this object     |
| `type`      | string | The type of data described by this object |
| `data`      | any    | Arbitrary custom data                     |


The `namespace` can be any URL that's defined in the `namespaces` array. The URL fragment is ignored when checking if the namespace is defined.

The `type` can be any arbitrary string describing the data, for example: `category`, `donation_url`, etc.

### Server Info

This object represents information about a server in response to a server info request. It must be returned in respoonse to a request to `/_profilefed/server`. The host and port of the URL discovered via WebFinger will be used to make this request.

The `pubkey` should be stored to check against further responses.

This response must include a message signature. It should be transferred via the `X-ProfileFed-Sig` header, which must contain an Ed25519 signature of the response encoded in base64. Except for the first time a server is contacted, the message must be verified against this signature before any further processing takes place. If the signature does not match, the response must be ignored and an error must be returned.

If the server switches to a new key, this message must be signed with every previously-used key. These signatures must be provided in `X-ProfileFed-Previous` headers, encoded as base64. If the public key doesn't match and there are no matching signatures, any responses signed with the new key must return an error and must not be processed.

**Properties:**

| Property         | Type   | Description                                      |
|------------------|--------|--------------------------------------------------|
| `server_name`    | string | Name of the server                               |
| `previous_names` | array  | List of previous names used by the server        |
| `pubkey`         | string | Base64-encoded Ed25519 public key of the server  |
