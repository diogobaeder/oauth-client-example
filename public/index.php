<?php

require __DIR__ . '/../vendor/autoload.php';

use League\OAuth2\Client\Provider\GenericProvider;
use Monolog\Formatter\LineFormatter;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;

const AUTH_SERVER_BASE = 'http://localhost:8888';
// The info below should represent production values, and not hard-coded.
const CLIENT_ID = 'some-id';
const CLIENT_SECRET = 'some-secret';

$provider = new GenericProvider([
    'clientId' => CLIENT_ID,
    'clientSecret' => CLIENT_SECRET,
    // This redirect URI should match the redirectUri assigned to the Client in the server.
    'redirectUri' => 'http://localhost:8889/',
    'urlAuthorize' => AUTH_SERVER_BASE . '/authorize',
    'urlAccessToken' => AUTH_SERVER_BASE . '/access_token',
    // The resource owner URL can be anywhere, actually, but usually it's in the Resource Server.
    // The Resource Server should have the public key to be able to decode the access token and respond with the owner
    // details.
    'urlResourceOwnerDetails' => AUTH_SERVER_BASE . '/resource-owner',
    'scopes' => 'some-scope'
]);

$logger = new Logger('example');
$handler = new StreamHandler(__DIR__ . '/../output.log');
$lineFormatter = new LineFormatter;
$lineFormatter-> includeStacktraces();
$handler->setFormatter($lineFormatter);
$logger->pushHandler($handler);

// If we don't have an authorization code then get one
if (!isset($_GET['code'])) {

    // Fetch the authorization URL from the provider; this returns the
    // urlAuthorize option and generates and applies any necessary parameters
    // (e.g. state).
    $authorizationUrl = $provider->getAuthorizationUrl();

    // Get the state generated for you and store it to the session.
    $_SESSION['oauth2state'] = $provider->getState();

    // Redirect the user to the authorization URL.
    header('Location: ' . $authorizationUrl);
    exit;

// Check given state against previously stored one to mitigate CSRF attack
} elseif (empty($_GET['state']) || (isset($_SESSION['oauth2state']) && $_GET['state'] !== $_SESSION['oauth2state'])) {

    if (isset($_SESSION['oauth2state'])) {
        unset($_SESSION['oauth2state']);
    }

    exit('Invalid state');

} else {

    try {
        // Try to get an access token using the authorization code grant.
        $accessToken = $provider->getAccessToken('authorization_code', [
            'code' => $_GET['code']
        ]);

        // We have an access token, which we may use in authenticated
        // requests against the service provider's API.
        echo 'Access Token: ' . $accessToken->getToken() . "<br>";
        echo 'Refresh Token: ' . $accessToken->getRefreshToken() . "<br>";
        echo 'Expired in: ' . $accessToken->getExpires() . "<br>";
        echo 'Already expired? ' . ($accessToken->hasExpired() ? 'expired' : 'not expired') . "<br>";

        // Using the access token, we may look up details about the
        // resource owner.
        $resourceOwner = $provider->getResourceOwner($accessToken);

        var_export($resourceOwner->toArray());

        // The provider provides a way to get an authenticated API request for
        // the service, using the access token; it returns an object conforming
        // to Psr\Http\Message\RequestInterface.
        $request = $provider->getAuthenticatedRequest(
            'GET',
            'https://service.example.com/resource',
            $accessToken
        );

    } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {

        // Failed to get the access token or user details.
        exit($e->getMessage());

    }

}
