<?php

namespace App\Services\Cognito;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Http;

class JWTVerifier
{
    /**
     * @param string $jwt
     * @return object|null
     */
    public function decode(string $jwt)
    {
        $tks = explode('.', $jwt);
        if (count($tks) !== 3) {
            return null;
        }
        [$headb64, $_, $_] = $tks;

        $jwks = $this->fetchJWKs();
        try {
            $kid = $this->getKid($headb64);
            $jwk = $this->getJWK($jwks, $kid);
            $alg = $this->getAlg($jwks, $kid);
            return JWT::decode($jwt, $jwk, [$alg]);
        } catch (\RuntimeException $exception) {
            return null;
        }
    }

    private function getKid(string $headb64)
    {
        $headb64 = json_decode(JWT::urlsafeB64Decode($headb64), true);
        if (array_key_exists('kid', $headb64)) {
            return $headb64['kid'];
        }
        throw new \RuntimeException();
    }

    private function getJWK(array $jwks, string $kid)
    {
        $keys = JWK::parseKeySet($jwks);
        if (array_key_exists($kid, $keys)) {
            return $keys[$kid];
        }
        throw new \RuntimeException();
    }

    private function getAlg(array $jwks, string $kid)
    {
        if (!array_key_exists('keys', $jwks)) {
            throw new \RuntimeException();
        }

        foreach ($jwks['keys'] as $key) {
            if ($key['kid'] === $kid && array_key_exists('alg', $key)) {
                return $key['alg'];
            }
        }
        throw new \RuntimeException();
    }

    private function fetchJWKs(): array
    {
        $response = Http::get('https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_Qlp3f7QlZ/.well-known/jwks.json');
        return json_decode($response->getBody()->getContents(), true) ?: [];
    }
}
