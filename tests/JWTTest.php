<?php

namespace Jsor\Stack;

class JWTTest extends \PHPUnit_Framework_TestCase
{
    /** @test */
    public function it_throws_exception_for_missing_key_provider()
    {
        $this->setExpectedException('RuntimeException');

        new JWT($this->getMock('Symfony\Component\HttpKernel\HttpKernelInterface'));
    }
}
