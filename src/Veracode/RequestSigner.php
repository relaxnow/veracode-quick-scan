<?php

namespace Veracode;

final class HmacRequestSigner
{
    // Included in the signature to inform Veracode of the signature version.
    private static $VERACODE_REQUEST_VERSION_STRING = "vcode_request_version_1";

    // Expected format for the unencrypted data string.
    private static $DATA_FORMAT = "id=%s&host=%s&url=%s&method=%s";

    // Expected format for the Authorization header.
    private static $HEADER_FORMAT = "%s id=%s,ts=%s,nonce=%s,sig=%s";

    // Expect prefix to the Authorization header.
    private static $VERACODE_HMAC_SHA_256 = "VERACODE-HMAC-SHA-256";

    // Charset to use when encrypting a string.
    private static $UTF_8 = "UTF-8";

    // Private constructor.
    private function HmacRequestSigner()
    {
        /*
         * This is a utility class that should only be accessed through its
         * static methods.
         */
    }

    /**
     * Entry point for HmacRequestSigner. Returns the value for the
     * Authorization header for use with Veracode APIs when provided an API id,
     * secret key, and target URL.
     *
     * @param id
     *            An API id for authentication
     * @param key
     *            The secret key corresponding to the API id
     * @param url
     *            The URL of the called API, including query parameters
     *
     * @return The value to be put in the Authorization header
     *
     * @throws UnsupportedEncodingException
     * @throws IllegalStateException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws \Exception
     */
    public static function getVeracodeAuthorizationHeader($id, $key, $url, $httpMethod)
    {
        $urlQuery = parse_url($url, PHP_URL_QUERY);
        $urlPath = parse_url($url, PHP_URL_PATH);
        if ($urlQuery) {
            $urlPath .= "?" . $urlQuery;
        }
        $data = sprintf(self::$DATA_FORMAT, $id, parse_url($url, PHP_URL_HOST), $urlPath, $httpMethod);
        $timestamp = round(microtime(true) * 1000);
        $nonce = bin2hex(random_bytes(16));
        $signature = self::getSignature($key, $data, $timestamp, $nonce);
        var_dump($signature);

        return sprintf(self::$HEADER_FORMAT, self::$VERACODE_HMAC_SHA_256, $id, $timestamp, $nonce, $signature);
    }

    /*
     * Generate the signature expected by the Veracode platform by chaining
     * encryption routines in the correct order.
     */
    private static function getSignature($key, $data, $timestamp, $nonce)
    {
        var_dump("Key: $key");
        $keyBytes = hex2bin($key);
        var_dump("nonce: $nonce");
        $nonceBytes = hex2bin($nonce);
        $encryptedNonce = self::hmacSha256($nonceBytes, $keyBytes);
        var_dump("encryptedNonce: " . bin2hex($encryptedNonce));
        $encryptedTimestamp = self::hmacSha256($timestamp, $encryptedNonce);
        var_dump("encryptedTimestamp: " . bin2hex($encryptedTimestamp));
        $signingKey = self::hmacSha256(self::$VERACODE_REQUEST_VERSION_STRING, $encryptedTimestamp);
        var_dump("signingKey: " . bin2hex($signingKey));
        $signature = self::hmacSha256($data, $signingKey);
        var_dump("signature: " . bin2hex($signature));
        return bin2hex($signature);
    }

    // Encrypt a string using the provided key.
    private static function hmacSha256($data, $key)
    {
        return hash_hmac("sha256", $data, $key, true);
    }
}
