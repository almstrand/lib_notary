notary
===========

Server-side library simplifying signing Google Cloud Storage HTTP requests to authorize file access (upload, download, etc.) via your website.

Sample usage
-----------

This sample code returns a signed URL that can ge requested (GET) to download specified file from Google Cloud Storage.

### GET (download) example
```
Notary.signGetRequest(
  "<my-storage-id>@developer.gserviceaccount.com",
  "my-private-key.pem",
  10 * 60 /* 10 min */,
  "my-bucket",
  "my-file.txt"
)
.catchError((e) {
  print("An error occurred: $e");
})
.then((SignedRequest signedRequest) {
  if (signedRequest != null) {
    print("Signed download URL: ${signedRequest.url}");
  }
});
```

### POST (upload) example

This sample code returns parameters to be specified in your HTML form element when uploading a file to Google Cloud Storage.

```
Notary.signPostRequest(
  "<my-storage-id>@developer.gserviceaccount.com",
  "my-private-key.pem",
  10 * 60 /* 10 min */,
  "my-bucket",
  "my-file.txt",
  "bucket-owner-read"
)
.catchError((e) {
  print("An error occurred: $e");
})
.then((SignedRequest signedRequest) {
  if (signedRequest != null) {
    RequestFormData requestFormData = signedRequest.requestFormData;
    print("URL: ${signedRequest.url}");
    print("Expiration: ${signedRequest.expiration}");
    print("Key: ${requestFormData.key}");
    print("GoogleAccessId: ${requestFormData.GoogleAccessId}");
    print("Policy: ${requestFormData.policy}");
    print("signature: ${requestFormData.signature}");
  }
});
```

Note
-----------
* The first parameter (googleAccessStorageId) is the email-form of the client ID. This ID can be viewed in the authentication section of the Google Cloud console.
* The .PEM file can be extracted from the .p12 file (obtained via the Google Cloud console) using openssl. E.g.: `openssl pkcs12 -nocerts -nodes -passin pass:notasecret -in my-private-key.p12 | openssl rsa -out my-private-key.pem`