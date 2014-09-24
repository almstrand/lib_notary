notary
===========

Server-side library to sign Google Cloud Storage requests and enable uploading or accessing Google Cloud Storage files directly from web applications without exposing private keys to end-users.

Sample usage
-----------

```
Notary.sign(
  "<my-storage-id>@developer.gserviceaccount.com",
  "my-private-key.pem",
  "GET",
  10 * 60 /* 10 min */,
  "/my-bucket/my-file.txt"
)
.catchError((e) {
  print("An error occured: $e");
})
.then((String signedUrl) {
  print("Signed URL: $signedUrl");
});
```

Note
-----------
* The first parameter (googleAccessStorageId) is the email-form of the client ID. This ID can be viewed in the authentication section of the Google Cloud console.
* The .PEM file can be extracted from the .p12 file (obtained via the Google Cloud console) using openssl. E.g.: `openssl pkcs12 -nocerts -nodes -passin pass:notasecret -in my-private-key.p12 | openssl rsa -out my-private-key.pem`