<?php

namespace Jsor\Stack;

use Dflydev\Stack\Firewall;
use Dflydev\Stack\WwwAuthenticateStackChallenge;
use Namshi\JOSE\SimpleJWS;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class JWT implements HttpKernelInterface
{
    private $app;
    private $options;

    public function __construct(HttpKernelInterface $app, array $options = [])
    {
        $this->app = $app;
        $this->options = $this->setupOptions($options);
    }

    public function handle(Request $request, $type = HttpKernelInterface::MASTER_REQUEST, $catch = true)
    {
        $challenge = function (Response $response, $error = null) {
            $value = 'Bearer';

            if (isset($this->options['realm'])) {
                $value .= sprintf(' realm="%s"', $this->options['realm']);
            }

            if ($error) {
                $value .= sprintf(' error="%s"', $error);
            }

            $response->headers->set('WWW-Authenticate', $value);

            return $response;
        };

        $authenticate = function ($app, $anonymous) use ($request, $type, $catch, $challenge) {
            $header = $request->headers->get('authorization');

            if (!preg_match('/^Bearer (.+)$/i', $header, $matches)) {
                if ($anonymous) {
                    return (new WwwAuthenticateStackChallenge($app, $challenge))
                        ->handle($request, $type, $catch);
                }

                return $challenge(
                    new Response('Invalid Authorization header (Format is: "Authorization: Bearer [token]")', 400),
                    'invalid_request'
                );
            }

            $token = $matches[1];

            try {
                $jws = SimpleJWS::load($token);
            } catch (\InvalidArgumentException $e) {
                return $challenge(
                    new Response('Invalid JSON Web Token', 401),
                    'invalid_token'
                );
            }

            if (!$jws->isValid($this->options['key_provider']())) {
                return $challenge(
                    new Response('Invalid JSON Web Token', 401),
                    'invalid_token'
                );
            }

            $request->attributes->set(
                'stack.authn.token',
                $this->options['token_translator']($jws->getPayload())
            );

            return $app->handle($request, $type, $catch);
        };

        return (new Firewall($this->app, [
                'challenge' => $challenge,
                'authenticate' => $authenticate,
                'firewall' => $this->options['firewall']
            ]))
            ->handle($request, $type, $catch);
    }

    private function setupOptions(array $options)
    {
        if (!isset($options['key_provider'])) {
            throw new \RuntimeException("No 'key_provider' callback specified");
        }

        if (!isset($options['token_translator'])) {
            $options['token_translator'] = function ($token) {
                return $token;
            };
        }

        if (!isset($options['firewall'])) {
            $options['firewall'] = [];
        }

        return $options;
    }
}
