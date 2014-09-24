library notary;

import 'dart:io';
import 'dart:async';
import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:googleapis_auth/src/crypto/rsa.dart';
import 'package:googleapis_auth/src/crypto/pem.dart';
import 'package:googleapis_auth/src/crypto/rsa_sign.dart';

class SignedRequest {
  
  /**
   * URL that may be used to access requested Google Cloud Storage file.
   */
  String url;
  
  /**
   * The verb that may be used with the signed URL. Signed URLs can be used with GET, HEAD, PUT, and DELETE requests. Although Signed URLs cannot be used with POST, you can use the POST signature parameters described in POST Object to authenticate using web forms.
   */
  String httpVerb;
  
  /**
   * The resource being addressed in the URL. For more details, see https://developers.google.com/storage/docs/accesscontrol#About-Canonical-Resources.
   */
  String canonicalizedResource;
  
  /**
   * Epoch time expressed in seconds, when the signed URL expires. The server will reject any requests received after this timestamp.
   */
  int expirationEpochTimeSeconds;
  
  /**
   * Construct new signed request.
   */
  SignedRequest(String this.url, String this.httpVerb, String this.canonicalizedResource, int this.expirationEpochTimeSeconds);
}

class Notary {

  /**
   * Cached private keys
   */
  static final Map<String, RSAPrivateKey> _privateKeys = new Map<String, RSAPrivateKey>();

  /**
   * Sign Google Cloud Storage request
   */
  static SignedRequest _sign(String googleAccessStorageId, RSAPrivateKey privateKey, String httpVerb, int expirationSeconds, String canonicalizedResource, {String contentMD5 : "", String contentType : "", String canonicalizedExtensionHeaders : "", bool useSSL : true}) {

    // Calculate absolute expiration time
    int secondsSinceEpoch = new DateTime.now().millisecondsSinceEpoch ~/ 1000;
    int expirationEpochTimeSeconds = secondsSinceEpoch + expirationSeconds;

    // Construct string to sign
    List<int> stringToSign = UTF8.encode(httpVerb + "\n" + contentMD5 + "\n" + contentType + "\n" + expirationEpochTimeSeconds.toString() + "\n" + canonicalizedExtensionHeaders + canonicalizedResource);

    // Sign payload
    var signer = new RS256Signer(privateKey);
    List<int> signedRequest = signer.sign(stringToSign);

    // Base64 encode
    String base64EncodedSignedRequest = CryptoUtils.bytesToBase64(signedRequest);

    // The Base64 encoded signature may contain characters not legal in URLs (specifically + and /). These values must be replaced by safe encodings (%2B and %2F, respectively.)
    base64EncodedSignedRequest = Uri.encodeQueryComponent(base64EncodedSignedRequest);//hash.replaceAll("+", "%2B").replaceAll("/", "%2F");

    // Form signed URL
    String url = "http${useSSL ? 's' : ''}://storage.googleapis.com${canonicalizedResource}?GoogleAccessId=${googleAccessStorageId}&Expires=${expirationEpochTimeSeconds.toString()}&Signature=${base64EncodedSignedRequest}";
    
    // Return signed request
    return new SignedRequest(url, httpVerb, canonicalizedResource, expirationEpochTimeSeconds);
  }

  /**
   * Sign Google Cloud Storage request.
   *
   * @param googleAccessStorageId
   *      Email form of the client ID (viewable in the authentication section of the Google Cloud console.)
   * @param pemFilePath
   *      Path to .PEM file containing Google Cloud private key. The .PEM file can be extracted from the Google-provided .p12 file using openssl. E.g.: openssl pkcs12 -nocerts -nodes -passin pass:notasecret -in my-private-key.p12 | openssl rsa -out my-private-key.pem. Example: "~/.ssh/my-private-key.pem"
   * @param httpVerb
   *      The verb to be used with the signed URL. Signed URLs can be used with GET, HEAD, PUT, and DELETE requests. Although Signed URLs cannot be used with POST, you can use the POST signature parameters described in POST Object to authenticate using web forms. Example: "GET"
   * @param expirationSeconds
   *      Required. Number of seconds the signed URL will be valid from the time it was generated using this method. The server will reject any requests received after this timestamp. Example: "10 * 60" (10 minutes)
   * @param canonicalizedResource
   *      Required. The resource being addressed in the URL. For more details, see https://developers.google.com/storage/docs/accesscontrol#About-Canonical-Resources. Example: "/bucket/objectname"
   * @param contentMD5
   *      Optional. The MD5 digest value in base64. If you provide this in the string, the client (usually a browser) must provide this HTTP header with this same value in its request. Example: "rmYdCNHKFXam78uCt7xQLw=="
   * @param contentType
   *      Optional. If you provide this value the client (browser) must provide this HTTP header set to the same value. Example: "text/plain"
   * @param canonicalizedExtensionHeaders
   *      Optional. If these headers are used, the server will check to make sure that the client provides matching values. For information about how to create canonical headers for signing, see https://developers.google.com/storage/docs/accesscontrol#About-CanonicalExtensionHeaders. Examples: "x-goog-acl:public-read\nx-goog-meta-foo:bar,baz\n"
   * @param useSSL
   *      Optional. Set to true to sign HTTPS URL.
   */
  static Future<SignedRequest> sign(String googleAccessStorageId, String pemFilePath, String httpVerb, int expirationSeconds, String canonicalizedResource, {String contentMD5 : "", String contentType : "", String canonicalizedExtensionHeaders : "", bool useSSL : true}) {

    // Completer used to defer signing request until private key file has been read
    Completer<SignedRequest> urlSigningCompleter = new Completer<SignedRequest>();

    // Do we have a cached key?
    RSAPrivateKey privateKey = _privateKeys[pemFilePath];
    if (privateKey != null) {

      // Yes, return URL signed using cached key
      SignedRequest signedRequest = _sign(googleAccessStorageId, privateKey, httpVerb, expirationSeconds, canonicalizedResource, contentMD5 : contentMD5, contentType : contentType, canonicalizedExtensionHeaders : canonicalizedExtensionHeaders, useSSL : useSSL);
      urlSigningCompleter.complete(signedRequest);
    }
    else {

      // No, read private key file
      Future<String> urlSignedFuture = new File(pemFilePath).readAsString().catchError((Object error) {
        urlSigningCompleter.completeError(error);
      }).then((String pemFileContents) {

        // Return null if error caught upon reading file
        if (pemFileContents == null) return null;

        // Parse PEM file
        privateKey = keyFromString(pemFileContents);

        // Cache private key
        _privateKeys[pemFilePath] = privateKey;

        // Return signed URL
        SignedRequest signedRequest = _sign(googleAccessStorageId, privateKey, httpVerb, expirationSeconds, canonicalizedResource, contentMD5 : contentMD5, contentType : contentType, canonicalizedExtensionHeaders : canonicalizedExtensionHeaders, useSSL : useSSL);
        urlSigningCompleter.complete(signedRequest);
      });
    };

    // Return future to be completed when the request is signed
    return urlSigningCompleter.future;
  }

}