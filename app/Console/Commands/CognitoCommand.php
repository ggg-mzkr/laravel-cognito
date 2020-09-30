<?php

namespace App\Console\Commands;

use App\Models\User;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Illuminate\Console\Command;

class CognitoCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'myapp:cognito {email} {password} {method}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Create User';

    private $library_version;
    private $region;
    private $access_key;
    private $secret_key;
    private $client_id;
    private $client_secret;
    private $user_pool_id;

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();

        $this->library_version = 'latest';
        $this->region          = env('AWS_DEFAULT_REGION');
        $this->access_key      = env('AWS_ACCESS_KEY_ID');
        $this->secret_key      = env('AWS_SECRET_ACCESS_KEY');
        $this->client_id       = env('AWS_COGNITO_CLIENT_ID');
        $this->client_secret   = env('AWS_COGNITO_CLIENT_SECRET');
        $this->user_pool_id    = env('AWS_COGNITO_USER_POOL_ID');
    }

    /**
     * Execute the console command.
     *
     * @return mixed
     */
    public function handle()
    {
        $email = $this->argument('email');
        $password = $this->argument('password');
        $method = $this->argument('method');

        if (!in_array($method, ['auth', 'signUp'])) {
            $this->output->error('method is allowed auth or signUp');
            return 1;
        }

        $this->$method($email, $password);
        return 0;
    }

    private function adminInstantiation()
    {
        return new CognitoIdentityProviderClient([
            'version' => $this->library_version,
            'region' => $this->region,
            'credentials' => [
                'key' => $this->access_key,
                'secret' => $this->secret_key,
            ],
        ]);
    }

    private function signUp(string $email, string $password)
    {
        $response = $this
            ->adminInstantiation()
            ->signUp([
                'ClientId' => $this->client_id,
                'Username' => $email,
                'Email' => $email,
                'Password' => $password,
                'UserAttributes' => [
                    [
                        'Name' => 'email',
                        'Value' => $email,
                    ]
                ],
                'SecretHash' => $this->cognitoSecretHash($email),
            ]);
        User::create(['email' => $email, 'cognito_sub' => $response->toArray()['UserSub'],]);
        $this->output->success(sprintf('created %s', $email));
    }

    private function auth(string $email, string $password)
    {
        $response = $this
            ->adminInstantiation()
            ->adminInitiateAuth([
                'AuthFlow' => 'ADMIN_USER_PASSWORD_AUTH',
                'ClientId' => $this->client_id,
                'UserPoolId' => $this->user_pool_id,
                'AuthParameters' => [
                    'USERNAME' => $email,
                    'PASSWORD' => $password,
                    'SECRET_HASH' => $this->cognitoSecretHash($email),
                ],
            ]);
        $this->output->success(sprintf('token for %s', $email));
        $this->output->writeln($response->toArray()['AuthenticationResult']['IdToken']);
    }

    protected function cognitoSecretHash($username)
    {
        $hash = hash_hmac('sha256', $username.$this->client_id, $this->client_secret, true);
        return base64_encode($hash);
    }

}
