part of notary;

/**
 * Data to be sent from client upon POSTing HTML form to upload file to AWS S3.
 */
class AWSRequestFormData {
}

/**
 * Structure containing URL relevant to signed request along with any HTTP form data to be included upon making request to AWS S3.
 */
class AWSSignedRequest {

  /**
   * HTTP parameters to be passed in HTTP body when performing a POST
   */
  AWSRequestFormData requestFormData;
}

/**
 * Defines methods to sign Amazon Web Services (AWS) S3 file upload/download requests.
 */
class AWSNotary {

}
