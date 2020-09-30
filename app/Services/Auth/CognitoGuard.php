<?php

namespace App\Services\Auth;

use App\Services\Cognito\JWTVerifier;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;

class CognitoGuard implements Guard
{
    use GuardHelpers;

    /**
     * @var JWTVerifier
     */
    private $JWTVerifier;

    /**
     * @var Request
     */
    private $request;

    /**
     * @var UserProvider
     */
    private $userProvider;

    /**
     * CognitoGuard constructor.
     * @param Request $request
     * @param UserProvider $userProvider
     * @param JWTVerifier $JWTVerifier
     */
    public function __construct(
        JWTVerifier $JWTVerifier,
        Request $request,
        UserProvider $userProvider
    ) {
        $this->JWTVerifier = $JWTVerifier;
        $this->request = $request;
        $this->userProvider = $userProvider;
    }

    public function user()
    {
        if ($this->user) {
            return $this->user;
        }

        $jwt = $this->request->bearerToken();
        if (!$jwt) {
            return null;
        }

        $decoded = $this->JWTVerifier->decode($jwt);
        if ($decoded) {
            return $this->user = $this->userProvider->retrieveByCredentials(['cognito_sub' => $decoded->sub]);
        }

        return null;
    }

    public function validate(array $credentials = [])
    {
        throw new RuntimeException('Cognito guard cannot be used for credential based authentication.');
    }
}
