<?php

namespace App\Providers;

use App\Services\Auth\CognitoGuard;
use App\Services\Cognito\JWTVerifier;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;

class AuthServiceProvider extends ServiceProvider
{
    /**
     * The policy mappings for the application.
     *
     * @var array
     */
    protected $policies = [
        // 'App\Models\Model' => 'App\Policies\ModelPolicy',
    ];

    /**
     * Register any authentication / authorization services.
     *
     * @return void
     */
    public function boot()
    {
        $this->registerPolicies();

        Auth::extend('cognito', function($app, $name, array $config) {
            return new CognitoGuard(
                new JWTVerifier(),
                $app['request'],
                Auth::createUserProvider($config['provider'])
            );
        });
    }
}
