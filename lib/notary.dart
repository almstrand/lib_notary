library notary;

import 'dart:io';
import 'dart:async';
import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:googleapis_auth/src/crypto/rsa.dart';
import 'package:googleapis_auth/src/crypto/pem.dart';
import 'package:googleapis_auth/src/crypto/rsa_sign.dart';

/**
 * Data to be sent from client upon POSTing HTML form to upload file to Google Cloud Storage.
 */
class RequestFormData {

  /**
   * The name of the key used to identify the file inside the bucket.
   */
  String key;

  /**
   * Email form of the client ID (viewable in the authentication section of the Google Cloud console.)
   */
  String GoogleAccessId;

  /**
   * Base-64 encoded policy document. This field is specified only for POST requests.
   */
  String policy;

  /**
   * Signature for policy document. This field is specified only for POST requests.
   */
  String signature;

  RequestFormData(String this.key, String this.GoogleAccessId, String this.policy, String this.signature);
}

/**
 * Structure containing URL relevant to signed request along with any HTTP form data to be included upon making request to Google Cloud Storage.
 */
class SignedRequest {

  /**
   * URL that may be used to access requested Google Cloud Storage file.
   */
  String url;

  /**
   * Epoch time, expressed in seconds, when the signed URL expires. The server will reject any requests received after this timestamp.
   */
  int expiration;

  /**
   * HTTP parameters to be passed in HTTP body when performing a POST
   */
  RequestFormData requestFormData;

  /**
   * Construct new signed request.
   */

  SignedRequest(String this.url, int this.expiration, { RequestFormData this.requestFormData : null});
}

class Notary {

  /**
   * Cached private keys
   */
  static final Map<String, RSAPrivateKey> _privateKeys = new Map<String, RSAPrivateKey>();

  /**
   * Get private key from cache or PEM file
   */
  static Future<RSAPrivateKey> _getPrivateKey(String pemFilePath, bool cachePrivateKeys) {

    // Completer used to conditionally defer responding with private key until read/parsed from file
    Completer<RSAPrivateKey> rsaPrivateKeyCompleter = new Completer<RSAPrivateKey>();

    // Do we have a cached key?
    RSAPrivateKey privateKey = _privateKeys[pemFilePath];
    if (privateKey != null) {

      // Yes, complete future referencing private key
      rsaPrivateKeyCompleter.complete(privateKey);
    } else {

      // No, read private key file
      Future<String> urlSignedFuture = new File(pemFilePath).readAsString().catchError((Object error) {
        rsaPrivateKeyCompleter.completeError(error);
      }).then((String pemFileContents) {

        // Return null if error caught upon reading the private key file
        if (pemFileContents == null) {
          rsaPrivateKeyCompleter.complete(null);
        }

        // Parse PEM file
        privateKey = keyFromString(pemFileContents);

        // Cache private key, if requested
        if (cachePrivateKeys) {
          _privateKeys[pemFilePath] = privateKey;
        }

        // Complete future referencing private key
        rsaPrivateKeyCompleter.complete(privateKey);
      });
    }

    // Return future to be completed once a private key is available
    return rsaPrivateKeyCompleter.future;
  }

  /**
   * Sign Google Cloud Storage HTTP GET request.
   *
   * @param GoogleAccessId
   *      Email form of the client ID (viewable in the authentication section of the Google Cloud console.)
   * @param pemFilePath
   *      Path to .PEM file containing Google Cloud private key. The .PEM file can be extracted from the Google-provided .p12 file using openssl. E.g.: openssl pkcs12 -nocerts -nodes -passin pass:notasecret -in my-private-key.p12 | openssl rsa -out my-private-key.pem. Example: "~/.ssh/my-private-key.pem"
   * @param expirationSeconds
   *      Required. Number of seconds the signed URL will be valid from the time it was generated using this method. The server will reject any requests received after this timestamp. Example: "10 * 60" (10 minutes)
   * @param bucketName
   *      Required. The name of the bucket where to upload or access the file. Example: "my-bucket"
   * @param key
   *      Required. The name of the key used to identify the file inside the bucket. Example: "test.txt"
   * @param contentMD5
   *      Optional. The MD5 digest value in base64. If you provide this in the string, the client (usually a browser) must provide this HTTP header with this same value in its request. Example: "rmYdCNHKFXam78uCt7xQLw=="
   * @param contentType
   *      Optional. If you provide this value the client (browser) must provide this HTTP header set to the same value. Example: "text/plain"
   * @param canonicalizedExtensionHeaders
   *      Optional. If these headers are used, the server will check to make sure that the client provides matching values. For information about how to create canonical headers for signing, see https://developers.google.com/storage/docs/accesscontrol#About-CanonicalExtensionHeaders. Examples: "x-goog-acl:public-read\nx-goog-meta-foo:bar,baz\n"
   * @param useSSL
   *      Optional. Set to true to produce an HTTPS URL.
   * @param cachePrivateKeys
   *      Optional. Set to true to cache private keys and improve speed performance of signing subsequent requests.
   */
  static Future<SignedRequest> signGetRequest(String GoogleAccessId, String pemFilePath, int expirationSeconds, String bucketName, String key, { String contentMD5 : "", String contentType : "", String canonicalizedExtensionHeaders : "", bool useSSL : true, bool cachePrivateKeys : true }) {

    // Completer used to defer signing request until private key file has been read
    Completer<SignedRequest> urlSigningCompleter = new Completer<SignedRequest>();

    // Get private key
    _getPrivateKey(pemFilePath, cachePrivateKeys).catchError((Object error) {
      urlSigningCompleter.completeError(error);
    }).then((RSAPrivateKey privateKey) {

      // Complete future if caught error when reading/parsing key file
      if (privateKey == null) {
        urlSigningCompleter.complete(null);
      } else {

        // Form canonicalized resource name (see https://developers.google.com/storage/docs/accesscontrol#About-Canonical-Resources.
        String canonicalizedResource = "/${bucketName}/${key}";

        // Calculate absolute expiration time
        int secondsSinceEpoch = new DateTime.now().millisecondsSinceEpoch ~/ 1000;
        int expirationEpochTimeSeconds = secondsSinceEpoch + expirationSeconds;

        // Build string to sign.
        List<int> stringToSign =
          UTF8.encode("GET\n" +
            contentMD5 + "\n" +
            contentType + "\n" +
            expirationEpochTimeSeconds.toString() + "\n" +
            canonicalizedExtensionHeaders + canonicalizedResource
          );

        // Sign
        var signer = new RS256Signer(privateKey);
        List<int> signedRequestBytes = signer.sign(stringToSign);

        // Base64 encode
        String base64EncodedSignedRequest = CryptoUtils.bytesToBase64(signedRequestBytes);

        // The Base64 encoded signature may contain characters not legal in URLs (specifically + and /). These values must be replaced by safe encodings (%2B and %2F, respectively.)
        base64EncodedSignedRequest = Uri.encodeQueryComponent(base64EncodedSignedRequest);//hash.replaceAll("+", "%2B").replaceAll("/", "%2F");

        // Add query string parameters (parameters not passed via HTTP body)
        String url = "http${useSSL ? 's' : ''}://${bucketName}.storage.googleapis.com/${key}?GoogleAccessId=${GoogleAccessId}&Expires=${expirationEpochTimeSeconds.toString()}&Signature=${base64EncodedSignedRequest}";

        // Instantiate signed request object
        SignedRequest signedRequest = new SignedRequest(url, expirationEpochTimeSeconds);

        // Complete future with signed request
        urlSigningCompleter.complete(signedRequest);
      }
    });

    // Return future to be completed when the request is signed
    return urlSigningCompleter.future;
  }

  /**
   * Sign Google Cloud Storage POST (upload) request.
   *
   * @param GoogleAccessId
   *      Email form of the client ID (viewable in the authentication section of the Google Cloud console.)
   * @param pemFilePath
   *      Path to .PEM file containing Google Cloud private key. The .PEM file can be extracted from the Google-provided .p12 file using openssl. E.g.: openssl pkcs12 -nocerts -nodes -passin pass:notasecret -in my-private-key.p12 | openssl rsa -out my-private-key.pem. Example: "~/.ssh/my-private-key.pem"
   * @param expirationSeconds
   *      Required. Number of seconds the signed URL will be valid from the time it was generated using this method. The server will reject any requests received after this timestamp. Example: "10 * 60" (10 minutes)
   * @param bucketName
   *      Required. The name of the bucket where to upload or access the file. Example: "my-bucket"
   * @param key
   *      Required. The name of the key used to identify the file inside the bucket. Example: "test.txt"
   * @param acl
   *      Conditionally required. The predefined ACL that you want to apply to the object that is being uploaded. Example: "bucket-owner-read"
   * @param useSSL
   *      Optional. Set to true to produce an HTTPS URL.
   * @param cachePrivateKeys
   *      Optional. Set to true to cache private keys and improve speed performance of signing subsequent requests.
   */
  static Future<SignedRequest> signPostRequest(String GoogleAccessId, String pemFilePath, int expirationSeconds, String bucketName, String key, String acl, { bool useSSL : true, bool cachePrivateKeys : true }) {

    // Completer used to defer signing request until private key file has been read
    Completer<SignedRequest> urlSigningCompleter = new Completer<SignedRequest>();

    // Get private key
    _getPrivateKey(pemFilePath, cachePrivateKeys).catchError((Object error) {
      urlSigningCompleter.completeError(error);
    }).then((RSAPrivateKey privateKey) {

      // Complete future if caught error when reading/parsing key file
      if (privateKey == null) {
        urlSigningCompleter.complete(null);
      } else {

        // Form GCS URL
        String url = "http${useSSL ? 's' : ''}://${bucketName}.storage.googleapis.com";

        // Generate ISO-8601 formatted datetime string that GCS likes
        int millisecondsSinceEpoch = new DateTime.now().millisecondsSinceEpoch;
        int expirationTimeSinceEpochMillis = millisecondsSinceEpoch + expirationSeconds * 1000;
        DateTime exprationDateTime = new DateTime.fromMillisecondsSinceEpoch(expirationTimeSinceEpochMillis);
        String iso8601ExpirationDate = exprationDateTime.toIso8601String();
        int millisecondDelimiterPos = iso8601ExpirationDate.indexOf(".");
        if (millisecondDelimiterPos > 0) {
          iso8601ExpirationDate = iso8601ExpirationDate.substring(0, millisecondDelimiterPos) + "Z";
        }

        // Add parameters to policy document
        String policyDocument =
          '{"expiration":"${iso8601ExpirationDate}",' +
          '"conditions":[' +
            '{"key": "${key}"},' +
            '{"acl": "${acl}"},' +
            '{"bucket": "${bucketName}"}' +
          ']}';

        // Base-64 encode policy document
        List<int> policyDocumentBytes = UTF8.encode(policyDocument);
        String base64EncodedPolicyDocument = CryptoUtils.bytesToBase64(policyDocumentBytes);

        // Sign policy document
        var signer = new RS256Signer(privateKey);
        List<int> base64EncodedPolicyDocumentBytes = UTF8.encode(base64EncodedPolicyDocument);
        List<int> signedPolicyDocument = signer.sign(base64EncodedPolicyDocumentBytes);

        // Base64 encode signature
        String base64EncodedPolicyDocumentSignature = CryptoUtils.bytesToBase64(signedPolicyDocument);

        // Instantiate class encapsulating HTTP POST form data
        RequestFormData requestFormData = new RequestFormData(key, GoogleAccessId, base64EncodedPolicyDocument, base64EncodedPolicyDocumentSignature);

        // Instantiate signed request object
        SignedRequest signedRequest = new SignedRequest(url, expirationTimeSinceEpochMillis ~/ 1000, requestFormData : requestFormData);

        // Complete future with signed request
        urlSigningCompleter.complete(signedRequest);
      }
    });

    // Return future to be completed when the request is signed
    return urlSigningCompleter.future;
  }

}