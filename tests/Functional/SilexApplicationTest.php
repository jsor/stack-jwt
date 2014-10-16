<?php

namespace Jsor\Stack\Functional;

use Jsor\Stack\JWT;
use Namshi\JOSE\JWS;
use Silex\Application;
use Stack\Inline;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Client;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Adapted from dflydev/dflydev-stack-hawk tests.
 */
class SilexApplicationTest extends \PHPUnit_Framework_TestCase
{
    /** @test */
    public function it_ignores_requests_not_firewalled()
    {
        $app = $this->createDecoratedApplication([
            'firewall' => [
                ['path' => '/foo'],
            ]
        ]);

        $client = new Client($app);
        $client->request('GET', '/');

        $this->assertEquals('Root.', $client->getResponse()->getContent());
    }

    /** @test */
    public function it_does_not_challenge_for_unprotected_resource()
    {
        $app = $this->createDecoratedApplication([
            'firewall' => [
                [
                    'path' => '/',
                    'anonymous' => true
                ],
            ]
        ]);

        $client = new Client($app);
        $client->request('GET', '/');

        $this->assertEquals('Root.', $client->getResponse()->getContent());
    }

    /** @test */
    public function it_challenges_for_protected_resource()
    {
        $app = $this->createDecoratedApplication([
            'firewall' => [
                [
                    'path' => '/',
                    'anonymous' => true
                ],
            ]
        ]);

        $client = new Client($app);
        $client->request('GET', '/protected/resource');

        $this->assertEquals(401, $client->getResponse()->getStatusCode());
        $this->assertEquals('Bearer realm="test"', $client->getResponse()->headers->get('WWW-Authenticate'));
    }

    /** @test */
    public function it_gets_expected_token()
    {
        $app = $this->createDecoratedApplication();

        $client = new Client($app);
        $client->request('GET', '/protected/token', [], [], [
            'HTTP_AUTHORIZATION' => sprintf('Bearer %s', $this->validToken())
        ]);

        $payload = json_decode($client->getResponse()->getContent(), true);
        unset($payload['iat']);

        $this->assertSame(200, $client->getResponse()->getStatusCode());
        $this->assertSame($this->payload(), $payload);
    }

    /**
     * @test
     * @dataProvider provideProtectedAndUnprotectedResources
     * @group 123
     */
    public function it_challenges_for_missing_header($resource)
    {
        $app = $this->createDecoratedApplication();

        $client = new Client($app);
        $client->request('GET', $resource, [], [], []);

        $this->assertEquals(401, $client->getResponse()->getStatusCode());
        $this->assertEquals('Bearer realm="test"', $client->getResponse()->headers->get('WWW-Authenticate'));
    }

    /**
     * @test
     * @dataProvider provideProtectedAndUnprotectedResources
     */
    public function it_challenges_for_invalid_header($resource)
    {
        $app = $this->createDecoratedApplication();

        $client = new Client($app);
        $client->request('GET', $resource, [], [], [
            'HTTP_AUTHORIZATION' => 'invalid'
        ]);

        $this->assertEquals(400, $client->getResponse()->getStatusCode());
        $this->assertEquals('Bearer realm="test" error="invalid_request"', $client->getResponse()->headers->get('WWW-Authenticate'));
    }

    /**
     * @test
     * @dataProvider provideProtectedAndUnprotectedResources
     */
    public function it_challenges_for_invalid_token($resource)
    {
        $app = $this->createDecoratedApplication();

        $client = new Client($app);
        $client->request('GET', $resource, [], [], [
            'HTTP_AUTHORIZATION' => sprintf('Bearer %s', $this->invalidToken())
        ]);

        $this->assertEquals(401, $client->getResponse()->getStatusCode());
        $this->assertEquals('Bearer realm="test" error="invalid_token"', $client->getResponse()->headers->get('WWW-Authenticate'));
    }

    /**
     * @test
     * @dataProvider provideProtectedAndUnprotectedResources
     */
    public function it_challenges_for_expired_token($resource)
    {
        $app = $this->createDecoratedApplication();

        $client = new Client($app);
        $client->request('GET', $resource, [], [], [
            'HTTP_AUTHORIZATION' => sprintf('Bearer %s', $this->expiredToken())
        ]);

        $this->assertEquals(401, $client->getResponse()->getStatusCode());
        $this->assertEquals('Bearer realm="test" error="invalid_token"', $client->getResponse()->headers->get('WWW-Authenticate'));
    }

    /**
     * @test
     * @dataProvider provideProtectedAndUnprotectedResources
     */
    public function it_allows_access_to_resource($resource, $expectedContent)
    {
        $app = $this->createDecoratedApplication();

        $client = new Client($app);
        $client->request('GET', $resource, [], [], [
            'HTTP_AUTHORIZATION' => sprintf('Bearer %s', $this->validToken())
        ]);

        $this->assertEquals(200, $client->getResponse()->getStatusCode());
        $this->assertEquals($expectedContent, $client->getResponse()->getContent());
    }

    /** @test */
    public function it_converts_WwwAuthenticateStack_to_bearer()
    {
        $authz = function(
            HttpKernelInterface $app,
            Request $request,
            $type = HttpKernelInterface::MASTER_REQUEST,
            $catch = true
        ) {
            // Simulate Authorization failure by returning 401 status
            // code with WWW-Authenticate: Stack.
            return new Response('', 401, [
                'WWW-Authenticate' => 'Stack'
            ]);
        };

        $app = $this->decorate(new Inline($this->application(), $authz));

        $client = new Client($app);
        $client->request('GET', '/');

        $this->assertEquals('Bearer realm="test"', $client->getResponse()->headers->get('WWW-Authenticate'));
    }

    /** @test */
    public function it_converts_WwwAuthenticateStack_to_bearer_for_unsupported_authorization()
    {
        $authz = function(
            HttpKernelInterface $app,
            Request $request,
            $type = HttpKernelInterface::MASTER_REQUEST,
            $catch = true
        ) {
            // Simulate Authorization failure by returning 401 status
            // code with WWW-Authenticate: Stack.
            return new Response('', 401, [
                'WWW-Authenticate' => 'Stack'
            ]);
        };

        $app = $this->decorate(new Inline($this->application(), $authz), [
            'firewall' => [
                [
                    'path' => '/protected/resource',
                    'anonymous' => true
                ],
            ]
        ]);

        $client = new Client($app);
        $client->request('GET', '/protected/resource', [], [], [
            'HTTP_AUTHORIZATION' => 'Foo bar'
        ]);

        $this->assertEquals('Bearer realm="test"', $client->getResponse()->headers->get('WWW-Authenticate'));
    }

    /** @test */
    public function it_does_not_clobber_existing_token()
    {
        $authnMiddleware = function(
            HttpKernelInterface $app,
            Request $request,
            $type = HttpKernelInterface::MASTER_REQUEST,
            $catch = true
        ) {
            // We are going to claim that we authenticated...
            $request->attributes->set('stack.authn.token', 'foo');

            // JWT should actually capture the WWW-Authenticate: Stack response
            // and challenge on its own.
            return $app->handle($request, $type, $catch);
        };

        $app = new Inline($this->decorate($this->application()), $authnMiddleware);

        $client = new Client($app);
        $client->request('GET', '/protected/token');

        $this->assertEquals(json_encode('foo'), $client->getResponse()->getContent());
    }

    /** * @test */
    public function shouldChallengeOnAuthorizationEvenIfOtherMiddlewareAuthenticated()
    {
        $authnMiddleware = function(
            HttpKernelInterface $app,
            Request $request,
            $type = HttpKernelInterface::MASTER_REQUEST,
            $catch = true
        ) {
            // We are going to claim that we authenticated...
            $request->attributes->set('stack.authn.token', 'foo');

            // JWT should actually capture the WWW-Authenticate: Stack response
            // and challenge on its own.
            return $app->handle($request, $type, $catch);
        };

        $authzMiddleware = function(
            HttpKernelInterface $app,
            Request $request,
            $type = HttpKernelInterface::MASTER_REQUEST,
            $catch = true
        ) {
            // Simulate Authorization failure by returning 401 status
            // code with WWW-Authenticate: Stack.
            $response = (new Response())->setStatusCode(401);
            $response->headers->set('WWW-Authenticate', 'Stack');

            return $response;
        };

        $app = new Inline($this->decorate(new Inline($this->application(), $authzMiddleware)), $authnMiddleware);

        $client = new Client($app);
        $client->request('GET', '/protected/token');

        $this->assertEquals(401, $client->getResponse()->getStatusCode());
        $this->assertEquals('Bearer realm="test"', $client->getResponse()->headers->get('www-authenticate'));
    }

    protected function payload()
    {
        return [
            'uid' => 1,
            'roles' => ['user', 'admin']
        ];
    }

    protected function validToken()
    {
        $jws  = new JWS('HS256');

        $jws->setPayload($this->payload());
        $jws->sign('s3cr3t');

        return $jws->getTokenString();
    }

    protected function expiredToken()
    {
        $jws  = new JWS('HS256');

        $jws->setPayload(['exp' => (new \DateTime('yesterday'))->format('U')] + $this->payload());
        $jws->sign('s3cr3t');

        return $jws->getTokenString();
    }

    protected function invalidToken()
    {
        return 'invalid';
    }

    public function provideProtectedAndUnprotectedResources()
    {
        return [
            ['/', 'Root.'],
            ['/protected/resource', 'Protected Resource.'],
        ];
    }

    protected function createDecoratedApplication(array $config = [])
    {
        return $this->decorate($this->application(), $config);
    }

    protected function application()
    {
        $app = new Application();
        $app['exception_handler']->disable();

        $app->get('/', function () {
            return 'Root.';
        });

        $app->get('/protected/resource', function () {
            return 'Protected Resource.';
        });

        $app->get('/protected/token', function (Request $request) {
            return new JsonResponse($request->attributes->get('stack.authn.token'));
        });

        // Simple Silex middleware to always let certain requests go through
        // and to always throw 401 responses in all other cases *unless*
        // stack.authn.token has been set correctly.
        $app->before(function (Request $request) {
            if (in_array($request->getRequestUri(), array('/'))) {
                return;
            }
            if (!$request->attributes->has('stack.authn.token')) {
                $response = (new Response())->setStatusCode(401);
                $response->headers->set('WWW-Authenticate', 'Stack');

                return $response;
            }
        });

        return $app;
    }

    protected function decorate(HttpKernelInterface $app, array $config = [])
    {
        $config = array_merge([
            'realm' => 'test',
            'key_provider' => function () {
                return 's3cr3t';
            }
        ], $config);

        return new JWT($app, $config);
    }
}
