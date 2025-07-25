<?php

namespace Lsupp\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;

class Yandex extends AbstractProvider
{
    use BearerAuthorizationTrait;

    /**
     * {@inheritdoc}
     */
    public function getBaseAuthorizationUrl()
    {
        return 'https://oauth.yandex.ru/authorize';
    }

    /**
     * {@inheritdoc}
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return 'https://oauth.yandex.ru/token';
    }

    /**
     * {@inheritdoc}
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return 'https://login.yandex.ru/info?format=json&oauth_token=' . $token->getToken();
    }

    /**
     * {@inheritdoc}
     */
    protected function getDefaultScopes()
    {
        return [];
    }

    /* ---------- Device-ID helpers ---------- */
    private function createDeviceId(): string
    {
        // Генерация UUID v4 (строка с дефисами)
        return sprintf(
            '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            random_int(0, 0xffff), random_int(0, 0xffff),
            random_int(0, 0xffff),
            random_int(0, 0x0fff) | 0x4000,
            random_int(0, 0x3fff) | 0x8000,
            random_int(0, 0xffff), random_int(0, 0xffff), random_int(0, 0xffff)
        );
    }

    /* ---------- PKCE helpers ---------- */
    private function createVerifier(): string
    {
        return bin2hex(random_bytes(64));
    }

    private function deriveChallenge(string $verifier): string
    {
        return rtrim(
            strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'),
            '='
        );
    }
	
    protected function getAuthorizationParameters(array $options): array
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $options = parent::getAuthorizationParameters($options);

        // PKCE
        if (!isset($options['code_challenge'])) {
            $verifier = $this->createVerifier();

            $options['code_challenge'] = $this->deriveChallenge($verifier);
            $options['code_challenge_method'] = 'S256';
            $_SESSION['ya_pkce_verifier']   = $verifier;
        }

        // device_id
        $deviceId                = $this->createDeviceId();
        $options['device_id']    = $deviceId;
        $_SESSION['device_id']   = $deviceId;

        $_SESSION['state']       = $options['state'];

        return $options;
    }

    public function getAccessToken($grant, array $options = [])
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        if (!isset($options['code_verifier']) && isset($_SESSION['ya_pkce_verifier'])) {
            $options['code_verifier'] = $_SESSION['ya_pkce_verifier'];
        }
        if (!isset($options['device_id']) && isset($_SESSION['device_id'])) {
            $options['device_id'] = $_SESSION['device_id'];
        }

        return parent::getAccessToken($grant, $options);
    }

    /**
     * {@inheritdoc}
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if (isset($data['error'])) {
            throw new IdentityProviderException(
                $data['error'] . ': ' .$data['error_description'],
                $response->getStatusCode(),
                $response
            );
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new YandexResourceOwner($response);
    }
}
