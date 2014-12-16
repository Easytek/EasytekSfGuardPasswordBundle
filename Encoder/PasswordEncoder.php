<?php

namespace Easytek\SfGuardPasswordBundle\Encoder;

use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;

class PasswordEncoder implements PasswordEncoderInterface
{
	public function encodePassword($raw, $salt)
	{
		$salted = $this->mergePasswordAndSalt($raw, $salt);
		$digest = hash('sha1', $salted, true);
		return bin2hex($digest);
	}

	protected function mergePasswordAndSalt($password, $salt)
	{
		return $salt . $password;
	}

	public function isPasswordValid($encoded, $raw, $salt)
	{
		return $this->encodePassword($raw, $salt) == $encoded;
	}
}
