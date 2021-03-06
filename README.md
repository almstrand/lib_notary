#notary

Server-side Dart library to generate URLs and HTTP POST parameters enabling upload or download of public or private
files to/from common cloud file storage services. The currently supported services are
[Google Cloud Storage](https://cloud.google.com/storage/) and [Amazon Web Service Simple Storage Service (AWS S3)]
(http://aws.amazon.com/s3/).

These operations should be performed server-side to prevent exposing private key files
(Google Cloud Storage) or secret access keys (AWS S3) in client code.

#Sample usage

## Google Cloud Storage

### GET (download) example

This sample code returns a signed URL that can ge requested (GET) to download specified file from Google Cloud Storage.

    GoogleCloudNotary.signGetRequest(
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

### POST (upload) example

This sample code returns parameters to be specified in your HTML form element when uploading a file to Google Cloud Storage.

    GoogleCloudNotary.signPostRequest(
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

The resulting parameters can be used in an HTML form as such:

    <form action="https://<my-bycket>.storage.googleapis.com" method="POST" enctype="multipart/form-data">
      <input type="text" name="key" value="<my-key>"/>
      <input type="hidden" name="GoogleAccessId" value="<my-access-id>">
      <input type="hidden" name="acl" value="bucket-owner-read">
      <input id="policy" type="hidden" name="policy" value="<my-policy>">
      <input id="signature" type="hidden" name="signature" value="<my-signature>">
      <input id="file" name="file" type="file">
      <input type="submit" value="Upload">
    </form>

###Note

* The first parameter (googleAccessStorageId) is the email-form of the client ID. This ID can be viewed in the authentication section of the Google Cloud console.
* The .PEM file can be extracted from the .p12 file (obtained via the Google Cloud console) using openssl. E.g.: `openssl pkcs12 -nocerts -nodes -passin pass:notasecret -in my-private-key.p12 | openssl rsa -out my-private-key.pem`

## AWS S3

In the works...
