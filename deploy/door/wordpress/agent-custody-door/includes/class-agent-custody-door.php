<?php
/**
 * The door's decision and its receipts, in PHP. This file does not call WordPress: the plugin file gives it the request,
 * the settings, and a function that makes HTTP requests. The test suite runs it with the PHP command line.
 *
 * The receipts have the format of the Node door (packages/receipts/src/door-core.ts), and `agent-custody verify`
 * checks them with the same checks.
 */

if ( class_exists( 'Agent_Custody_Door' ) ) {
	return;
}

class Agent_Custody_Door {
	const VERSION                = '0.1.0';
	const RECEIPT_TYPE           = 'application/vnd.in-toto+json';
	const RECEIPT_PREDICATE      = 'https://agent-custody.dev/receipt/v0.2';
	const AUTHORIZATION_PREDICATE = 'https://agent-custody.dev/authorization/v0.1';
	const TREEHEAD_TYPE          = 'application/vnd.agent-custody.treehead+json';
	const STATEMENT_TYPE         = 'https://in-toto.io/Statement/v1';
	const CHALLENGE_HEADER       = 'x-agent-custody-challenge';
	const MAX_CHALLENGE_TOKEN    = 4096;
	const MAX_DECLARED           = 256;
	// The sender chooses the path and the headers, so a receipt keeps this much of each.
	const MAX_RECORDED           = 1024;
	const ROUTES                 = array( 'comment', 'login', 'register', 'lostpassword' );
	// The actions of wp-login.php that are not a login, a registration, or a lost password. The door does not decide them.
	const LOGIN_OTHER = array( 'logout', 'postpass', 'resetpass', 'rp', 'checkemail', 'confirmaction', 'confirm_admin_email', 'entered_recovery_mode' );

	// The SPKI DER encoding of an Ed25519 public key is this prefix and the 32 bytes of the key.
	const SPKI_PREFIX = '302a300506032b6570032100';

	const VERIFY_URL = array(
		'turnstile' => 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
		'hcaptcha'  => 'https://api.hcaptcha.com/siteverify',
	);
	// The field in which each provider's widget posts its token.
	const TOKEN_FIELD = array(
		'turnstile' => 'cf-turnstile-response',
		'hcaptcha'  => 'h-captcha-response',
	);
	// A fault of the provider or of the keys, not of the token: `unavailable`, never `failed`.
	const PROVIDER_FAULTS = array( 'internal-error', 'missing-input-secret', 'invalid-input-secret', 'bad-request', 'sitekey-secret-mismatch', 'invalid-sitekey', 'missing-sitekey', 'invalid-remoteip' );

	const POLICY_HUMANS = <<<'CEDAR'
// A user who is signed in to this WordPress site, on a form that is not about an account: wp-login.php takes a
// login, a registration, or a lost password from a sender who is signed in already.
permit(principal, action, resource) when { context.facts.wordpress.loggedIn && ["comment", "form"].contains(context.facts.arrival.route) };
// A visitor who passed the challenge.
permit(principal, action, resource) when { context.facts.arrival has challenge && context.facts.arrival.challenge.outcome == "passed" };

CEDAR;

	const POLICY_STRICT = <<<'CEDAR'
// A visitor who passed the challenge. A signed-in user must pass it too.
permit(principal, action, resource) when { context.facts.arrival has challenge && context.facts.arrival.challenge.outcome == "passed" };

CEDAR;

	/**
	 * The presets. Each one is a Cedar policy text and whether the door enforces it. PHP has no Cedar engine, so
	 * `evaluate` decides each text by hand, and the test suite checks each decision against Cedar. `watch` records
	 * what `humans` decides and refuses nothing.
	 */
	public static function presets() {
		return array(
			'watch'  => array( 'policy' => self::POLICY_HUMANS, 'enforced' => false ),
			'humans' => array( 'policy' => self::POLICY_HUMANS, 'enforced' => true ),
			'strict' => array( 'policy' => self::POLICY_STRICT, 'enforced' => true ),
		);
	}

	// ---- canonical JSON, digests, keys, DSSE ----

	/** Deterministic JSON, the same bytes as `canonicalize` in crypto.ts: sorted keys, no whitespace. An empty map must be an object, because an empty PHP array is a list. */
	public static function canonicalize( $value ) {
		$json = json_encode( self::sorted( $value ), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS | JSON_INVALID_UTF8_SUBSTITUTE );
		if ( false === $json ) {
			throw new RuntimeException( 'the value cannot be written as JSON: ' . json_last_error_msg() );
		}
		return $json;
	}

	private static function sorted( $value ) {
		if ( $value instanceof stdClass ) {
			$map = (array) $value;
		} elseif ( is_array( $value ) ) {
			if ( array_keys( $value ) === range( 0, count( $value ) - 1 ) || array() === $value ) {
				return array_map( array( __CLASS__, 'sorted' ), $value );
			}
			$map = $value;
		} else {
			return $value;
		}
		ksort( $map, SORT_STRING );
		$out = new stdClass();
		foreach ( $map as $k => $v ) {
			$out->{$k} = self::sorted( $v );
		}
		return $out;
	}

	public static function digest_of( $value ) {
		return hash( 'sha256', self::canonicalize( $value ) );
	}

	/** A new Ed25519 signing key, base64. */
	public static function new_key() {
		return base64_encode( sodium_crypto_sign_secretkey( sodium_crypto_sign_keypair() ) );
	}

	private static function public_raw( $key ) {
		return sodium_crypto_sign_publickey_from_secretkey( base64_decode( $key ) );
	}

	/** keyid = sha256 of the SPKI DER encoding of the public key, as `keyidOf` in crypto.ts. */
	public static function keyid( $key ) {
		return hash( 'sha256', hex2bin( self::SPKI_PREFIX ) . self::public_raw( $key ) );
	}

	/** The public key as SPKI PEM: the file that `agent-custody verify --issuer-key` reads. */
	public static function public_pem( $key ) {
		return "-----BEGIN PUBLIC KEY-----\n" . base64_encode( hex2bin( self::SPKI_PREFIX ) . self::public_raw( $key ) ) . "\n-----END PUBLIC KEY-----\n";
	}

	private static function pae( $type, $payload ) {
		return 'DSSEv1 ' . strlen( $type ) . ' ' . $type . ' ' . strlen( $payload ) . ' ' . $payload;
	}

	public static function dsse_sign( $type, $payload, $key ) {
		$bytes = self::canonicalize( $payload );
		$sig   = sodium_crypto_sign_detached( self::pae( $type, $bytes ), base64_decode( $key ) );
		return array(
			'payloadType' => $type,
			'payload'     => base64_encode( $bytes ),
			'signatures'  => array( array( 'keyid' => self::keyid( $key ), 'sig' => base64_encode( $sig ) ) ),
		);
	}

	/** The payload of an envelope that one of the keys signed (`keys` is keyid => base64 raw public key), or null. */
	public static function dsse_verify( $envelope, array $keys ) {
		if ( ! is_array( $envelope ) || ! isset( $envelope['payload'], $envelope['payloadType'], $envelope['signatures'] ) || ! is_string( $envelope['payload'] ) || ! is_string( $envelope['payloadType'] ) || ! is_array( $envelope['signatures'] ) ) {
			return null;
		}
		$payload = base64_decode( $envelope['payload'], true );
		if ( false === $payload ) {
			return null;
		}
		foreach ( $envelope['signatures'] as $s ) {
			if ( ! is_array( $s ) || ! isset( $s['keyid'], $s['sig'] ) || ! is_string( $s['keyid'] ) || ! is_string( $s['sig'] ) || ! isset( $keys[ $s['keyid'] ] ) ) {
				continue;
			}
			$sig = base64_decode( $s['sig'], true );
			$pub = base64_decode( $keys[ $s['keyid'] ], true );
			if ( false === $sig || false === $pub || SODIUM_CRYPTO_SIGN_BYTES !== strlen( $sig ) || SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== strlen( $pub ) ) {
				return null;
			}
			if ( ! sodium_crypto_sign_verify_detached( $sig, self::pae( $envelope['payloadType'], $payload ), $pub ) ) {
				return null;
			}
			$decoded = json_decode( $payload, true );
			return is_array( $decoded ) ? $decoded : null;
		}
		return null;
	}

	// ---- the log ----

	/** The keys in a log's key document (`/.well-known/agent-custody-log.json`), as keyid => base64 raw public key. */
	public static function parse_log_keys( $json ) {
		$doc = json_decode( $json, true );
		if ( ! is_array( $doc ) || empty( $doc['keys'] ) || ! is_array( $doc['keys'] ) ) {
			throw new RuntimeException( 'the log lists no keys' );
		}
		$keys = array();
		foreach ( $doc['keys'] as $k ) {
			$der = is_array( $k ) && isset( $k['publicKeyPem'] ) && is_string( $k['publicKeyPem'] ) ? base64_decode( preg_replace( '/-----[A-Z ]+-----|\s+/', '', $k['publicKeyPem'] ), true ) : false;
			if ( false === $der || 44 !== strlen( $der ) || bin2hex( substr( $der, 0, 12 ) ) !== self::SPKI_PREFIX ) {
				throw new RuntimeException( 'the log lists a key that is not an Ed25519 public key' );
			}
			$keyid = hash( 'sha256', $der );
			if ( ! isset( $k['keyid'] ) || $k['keyid'] !== $keyid ) {
				throw new RuntimeException( 'the log lists a key under a keyid that is not the keyid of that key' );
			}
			$keys[ $keyid ] = base64_encode( substr( $der, 12 ) );
		}
		return $keys;
	}

	/** The id that a hosted log writes into each tree head: the tenant in `/t/<tenant>/`. Null for a log with one tenant. */
	public static function log_id( $url ) {
		return preg_match( '#/t/([A-Za-z0-9_.-]+)/?$#', (string) parse_url( $url, PHP_URL_PATH ), $m ) ? $m[1] : null;
	}

	public static function leaf_hash( array $envelope ) {
		return hash( 'sha256', "\x00" . self::canonicalize( $envelope ) );
	}

	/** RFC 9162 section 2.1.3.2, as `verifyInclusion` in merkle.ts. */
	public static function verify_inclusion( $leaf_hash, $proof, $root ) {
		$hex = '/^[0-9a-f]{64}$/';
		if ( ! is_array( $proof ) || ! isset( $proof['leafIndex'], $proof['treeSize'], $proof['hashes'] ) || ! is_int( $proof['leafIndex'] ) || ! is_int( $proof['treeSize'] ) || ! is_array( $proof['hashes'] ) ) {
			return false;
		}
		$fn = $proof['leafIndex'];
		$sn = $proof['treeSize'] - 1;
		if ( $fn < 0 || $fn > $sn || ! is_string( $root ) || ! preg_match( $hex, $root ) || ! preg_match( $hex, $leaf_hash ) ) {
			return false;
		}
		$r = hex2bin( $leaf_hash );
		foreach ( $proof['hashes'] as $h ) {
			if ( 0 === $sn || ! is_string( $h ) || ! preg_match( $hex, $h ) ) {
				return false;
			}
			$p = hex2bin( $h );
			if ( 1 === $fn % 2 || $fn === $sn ) {
				$r = hash( 'sha256', "\x01" . $p . $r, true );
				while ( 0 === $fn % 2 && 0 !== $fn ) {
					$fn >>= 1;
					$sn >>= 1;
				}
			} else {
				$r = hash( 'sha256', "\x01" . $r . $p, true );
			}
			$fn >>= 1;
			$sn >>= 1;
		}
		return 0 === $sn && hash_equals( $root, bin2hex( $r ) );
	}

	/**
	 * Appends the envelope to the log as its leaf hash: the log commits to the receipt and never holds it. The answer
	 * is not taken on trust. The tree head must be signed by a pinned key of the log, must name the log, and the
	 * inclusion proof must put this leaf under the signed root. Throws when the log refuses or the answer does not check.
	 *
	 * `log` is `url`, `token`, and `keys` (keyid => base64 raw public key). `http` is
	 * `function ( $method, $url, array $headers, $body ): array( $status, $body )`, which throws when there is no answer
	 * and does not follow a redirect.
	 */
	public static function append( array $envelope, array $log, callable $http ) {
		$leaf_hash = self::leaf_hash( $envelope );
		$headers   = array( 'content-type' => 'application/json' );
		if ( ! empty( $log['token'] ) ) {
			$headers['authorization'] = 'Bearer ' . $log['token'];
		}
		list( $status, $body ) = $http( 'POST', rtrim( $log['url'], '/' ) . '/append', $headers, json_encode( array( 'leafHash' => $leaf_hash ) ) );
		if ( $status < 200 || $status > 299 ) {
			throw new RuntimeException( 'the log refused the append: ' . $status . ' ' . substr( (string) $body, 0, 200 ) );
		}
		$answer = json_decode( $body, true );
		if ( ! is_array( $answer ) || ! isset( $answer['treeHead'], $answer['inclusion'] ) ) {
			throw new RuntimeException( 'the log returned a malformed append result' );
		}
		$head = self::dsse_verify( $answer['treeHead'], $log['keys'] );
		if ( null === $head || self::TREEHEAD_TYPE !== $answer['treeHead']['payloadType'] ) {
			throw new RuntimeException( 'the log answered with a tree head that does not verify against its pinned keys' );
		}
		$log_id = self::log_id( $log['url'] );
		if ( null !== $log_id && ( ! isset( $head['log'] ) || $head['log'] !== $log_id ) ) {
			throw new RuntimeException( 'the log signed a tree head for another log' );
		}
		if ( ! isset( $head['treeSize'], $head['rootHash'], $answer['inclusion']['treeSize'] ) || $head['treeSize'] !== $answer['inclusion']['treeSize'] ) {
			throw new RuntimeException( 'the log answered with a tree head and a proof for different tree sizes' );
		}
		if ( ! self::verify_inclusion( $leaf_hash, $answer['inclusion'], $head['rootHash'] ) ) {
			throw new RuntimeException( 'the log answered with an inclusion proof that does not place this leaf under the signed root' );
		}
		return array( 'treeHead' => $answer['treeHead'], 'inclusion' => $answer['inclusion'] );
	}

	// ---- the arrival ----

	/** The segments of a path: decoded once, in lower case, with no empty, `.` or `..` segment. */
	private static function segments( $path ) {
		$out = array();
		foreach ( explode( '/', strtolower( rawurldecode( (string) $path ) ) ) as $segment ) {
			if ( '..' === $segment ) {
				array_pop( $out );
			} elseif ( '' !== $segment && '.' !== $segment ) {
				$out[] = $segment;
			}
		}
		return $out;
	}

	/**
	 * A path as the web server and WordPress read it: its segments after the path of the site's address (`home`), with
	 * no `index.php` at the start, no trailing slash, and nothing after a script name. Two paths that reach one form
	 * have one normal path, so a sender cannot spell a protected path in a way that the list does not match.
	 */
	public static function normal_path( $path, $home = '' ) {
		$segments = self::segments( $path );
		$home     = self::segments( $home );
		if ( $home && array_slice( $segments, 0, count( $home ) ) === $home ) {
			$segments = array_slice( $segments, count( $home ) );
		}
		if ( $segments && 'index.php' === $segments[0] ) {
			array_shift( $segments );
		}
		foreach ( $segments as $i => $segment ) {
			if ( '.php' === substr( $segment, -4 ) ) {
				$segments = array_slice( $segments, 0, $i + 1 );
				break;
			}
		}
		return '/' . implode( '/', $segments );
	}

	/**
	 * The route of a request, or null when the door does not protect it. `protect` lists the stock forms that are
	 * protected. `paths` are more paths, each exact or with a `/*` suffix, under the route `form`. `path` is the
	 * request path, or a list of the paths that the request reaches (the REST route can also come in the query).
	 * `home` is the path of the site's address: the listed paths start after it.
	 */
	public static function route( $pagenow, $action, $path, array $protect, array $paths, $home = '' ) {
		$route = null;
		if ( 'wp-comments-post.php' === $pagenow || 'wp-trackback.php' === $pagenow ) {
			$route = 'comment';
		} elseif ( 'wp-signup.php' === $pagenow ) {
			$route = 'register';
		} elseif ( 'wp-login.php' === $pagenow ) {
			// wp-login.php signs in on each action that it does not know, so each action that is not in a list here is a login.
			if ( 'register' === $action ) {
				$route = 'register';
			} elseif ( in_array( $action, array( 'lostpassword', 'retrievepassword' ), true ) ) {
				$route = 'lostpassword';
			} elseif ( ! in_array( $action, self::LOGIN_OTHER, true ) ) {
				$route = 'login';
			}
		}
		if ( null !== $route && in_array( $route, $protect, true ) ) {
			return $route;
		}
		foreach ( (array) $path as $candidate ) {
			$candidate = rtrim( self::normal_path( $candidate, $home ), '/' ) . '/';
			foreach ( $paths as $p ) {
				$prefix = '/*' === substr( $p, -2 );
				$base   = rtrim( self::normal_path( $prefix ? substr( $p, 0, -2 ) : $p ), '/' ) . '/';
				if ( $candidate === $base || ( $prefix && 0 === strpos( $candidate, $base ) ) ) {
					return 'form';
				}
			}
		}
		return null;
	}

	/**
	 * What the door observed about one arrival: the `arrival` fact. `headers` has lowercase names. This door checks no
	 * grant, signature, or passport, so an arrival that presents one is `claimed`, never `verified`.
	 */
	public static function arrival( array $headers, $remote, $method, $path, $route, $challenge ) {
		$declared = isset( $headers['x-agent-custody-agent'] ) ? substr( trim( $headers['x-agent-custody-agent'] ), 0, self::MAX_DECLARED ) : '';
		$grant    = isset( $headers['x-agent-custody-grant'] );
		$signed   = isset( $headers['signature-input'] );
		$passport = isset( $headers['x-agent-custody-passport'] );
		$arrival  = array(
			'class'     => $grant || $signed || $passport || '' !== $declared ? 'claimed' : 'unknown',
			'subject'   => '' !== $declared ? $declared : 'unknown',
			'grant'     => $grant ? 'invalid' : 'absent',
			'signature' => $signed ? 'unchecked' : 'absent',
			'remote'    => (string) $remote,
			'method'    => $method,
			'path'      => substr( (string) $path, 0, self::MAX_RECORDED ),
			'route'     => $route,
		);
		if ( $grant ) {
			$arrival['grantError'] = 'the WordPress door does not check grants';
		}
		if ( '' !== $declared ) {
			$arrival['declared'] = $declared;
		}
		if ( $passport ) {
			$arrival['passport'] = array( 'outcome' => 'unchecked' );
		}
		if ( null !== $challenge ) {
			$arrival['challenge'] = $challenge;
		}
		return $arrival;
	}

	/**
	 * Asks the provider whether the token is good, as `verifyChallengeToken` in door-core.ts. `success` is not
	 * sufficient: the token must come from one of the site's hostnames. The secret and the token go to the provider only.
	 * `challenge` is `provider`, `siteKey`, `secret`, and `hostnames` (lowercase).
	 */
	public static function check_challenge( array $challenge, $token, callable $http ) {
		$provider = $challenge['provider'];
		$token    = trim( (string) $token );
		if ( '' === $token ) {
			return array( 'provider' => $provider, 'outcome' => 'absent' );
		}
		if ( strlen( $token ) > self::MAX_CHALLENGE_TOKEN ) {
			return array( 'provider' => $provider, 'outcome' => 'failed', 'error' => 'the token is longer than ' . self::MAX_CHALLENGE_TOKEN . ' characters and was not sent to the provider' );
		}
		$fields = array( 'secret' => $challenge['secret'], 'response' => $token );
		if ( 'hcaptcha' === $provider ) {
			$fields['sitekey'] = $challenge['siteKey'];
		}
		try {
			list( $status, $body ) = $http( 'POST', self::VERIFY_URL[ $provider ], array( 'content-type' => 'application/x-www-form-urlencoded' ), http_build_query( $fields, '', '&' ) );
		} catch ( Exception $e ) {
			return array( 'provider' => $provider, 'outcome' => 'unavailable', 'error' => $e->getMessage() );
		}
		if ( $status < 200 || $status > 299 ) {
			return array( 'provider' => $provider, 'outcome' => 'unavailable', 'error' => 'the provider answered ' . $status );
		}
		$answer = json_decode( $body, true );
		if ( ! is_array( $answer ) ) {
			return array( 'provider' => $provider, 'outcome' => 'unavailable', 'error' => 'the provider answered with something that is not JSON' );
		}
		if ( ! isset( $answer['success'] ) || true !== $answer['success'] ) {
			$codes = isset( $answer['error-codes'] ) && is_array( $answer['error-codes'] ) ? array_values( array_filter( $answer['error-codes'], 'is_string' ) ) : array();
			if ( array_intersect( $codes, self::PROVIDER_FAULTS ) ) {
				return array( 'provider' => $provider, 'outcome' => 'unavailable', 'error' => 'the provider could not check the token: ' . implode( ', ', $codes ) );
			}
			return array( 'provider' => $provider, 'outcome' => 'failed', 'error' => $codes ? implode( ', ', $codes ) : 'the provider refused the token' );
		}
		$host = isset( $answer['hostname'] ) && is_string( $answer['hostname'] ) ? strtolower( $answer['hostname'] ) : null;
		if ( null === $host || ! in_array( $host, $challenge['hostnames'], true ) ) {
			return array( 'provider' => $provider, 'outcome' => 'failed', 'error' => 'the token was issued on ' . ( null === $host ? 'no hostname' : $host ) . ', not a hostname of this site' );
		}
		return array( 'provider' => $provider, 'outcome' => 'passed' );
	}

	// ---- the decision ----

	/** The preset's decision for an arrival: what Cedar answers for the preset's policy text. Fails closed: an unknown preset denies. */
	public static function evaluate( $preset, array $arrival, $logged_in ) {
		$presets = self::presets();
		if ( ! isset( $presets[ $preset ] ) ) {
			return array( 'decision' => 'deny', 'reasons' => array(), 'errors' => array( 'unknown preset' ), 'policyDigest' => hash( 'sha256', '' ) );
		}
		$passed  = isset( $arrival['challenge']['outcome'] ) && 'passed' === $arrival['challenge']['outcome'];
		$reasons = array();
		if ( self::POLICY_STRICT === $presets[ $preset ]['policy'] ) {
			if ( $passed ) {
				$reasons[] = 'policy0';
			}
		} else {
			if ( $logged_in && in_array( $arrival['route'], array( 'comment', 'form' ), true ) ) {
				$reasons[] = 'policy0';
			}
			if ( $passed ) {
				$reasons[] = 'policy1';
			}
		}
		$policy = array(
			'decision'     => $reasons ? 'allow' : 'deny',
			'reasons'      => $reasons,
			'errors'       => array(),
			'policyDigest' => hash( 'sha256', $presets[ $preset ]['policy'] ),
		);
		if ( ! $presets[ $preset ]['enforced'] ) {
			$policy['enforced'] = false;
		}
		return $policy;
	}

	public static function receipt_id() {
		$b    = random_bytes( 16 );
		$b[6] = chr( ord( $b[6] ) & 0x0f | 0x40 );
		$b[8] = chr( ord( $b[8] ) & 0x3f | 0x80 );
		return vsprintf( '%s%s-%s-%s-%s-%s%s%s', str_split( bin2hex( $b ), 4 ) );
	}

	/**
	 * Decides one arrival. Returns `head` (the receipt without its outcome), `forward` (WordPress may handle the
	 * request), and `denied` (the execution of a refused arrival, or null).
	 *
	 * The receipt records the method, the path, and four headers. It does not record the query or the body.
	 */
	public static function decide( $key, $preset, array $arrival, array $headers, $logged_in ) {
		$recorded = new stdClass();
		foreach ( array( 'user-agent', 'content-type', 'accept', 'host' ) as $name ) {
			if ( isset( $headers[ $name ] ) ) {
				$recorded->{$name} = substr( $headers[ $name ], 0, self::MAX_RECORDED );
			}
		}
		$args      = array( 'method' => $arrival['method'], 'path' => $arrival['path'], 'headers' => $recorded );
		$wordpress = array( 'loggedIn' => (bool) $logged_in );
		$policy    = self::evaluate( $preset, $arrival, $logged_in );
		$micro     = microtime( true );
		$head      = array(
			'receiptId' => self::receipt_id(),
			'timestamp' => gmdate( 'Y-m-d\TH:i:s', (int) $micro ) . sprintf( '.%03dZ', (int) ( ( $micro - floor( $micro ) ) * 1000 ) ),
			'issuer'    => array( 'kind' => 'door', 'keyid' => self::keyid( $key ), 'version' => self::VERSION, 'framework' => 'wordpress' ),
			'principal' => array( 'id' => null, 'provenance' => 'claimed' ),
			'agent'     => array( 'id' => $arrival['subject'], 'provenance' => 'claimed' ),
			'tool'      => array( 'name' => $arrival['route'], 'provenance' => 'observed' ),
			'request'   => array( 'args' => $args, 'argsDigest' => self::digest_of( $args ), 'provenance' => 'claimed' ),
			'facts'     => array(
				'arrival'   => array( 'tool' => 'door.arrival', 'args' => new stdClass(), 'value' => $arrival, 'resultDigest' => self::digest_of( $arrival ), 'provenance' => 'observed' ),
				'wordpress' => array( 'tool' => 'wordpress.user', 'args' => new stdClass(), 'value' => $wordpress, 'resultDigest' => self::digest_of( $wordpress ), 'provenance' => 'observed' ),
			),
			'policy'    => $policy + array( 'provenance' => 'observed' ),
		);
		$forward   = 'allow' === $policy['decision'] || isset( $policy['enforced'] );
		return array(
			'head'    => $head,
			'forward' => $forward,
			'denied'  => $forward ? null : array( 'status' => 'denied', 'reason' => 'no permit policy matched', 'provenance' => 'observed' ),
		);
	}

	private static function statement( $type, array $predicate ) {
		return array(
			'_type'         => self::STATEMENT_TYPE,
			'subject'       => array( array( 'name' => 'tool-call:' . $predicate['tool']['name'] . ':' . $predicate['receiptId'], 'digest' => array( 'sha256' => $predicate['request']['argsDigest'] ) ) ),
			'predicateType' => $type,
			'predicate'     => $predicate,
		);
	}

	/** The signed authorization: what the door commits to the log before WordPress handles the request. */
	public static function authorization( array $head, $key ) {
		return self::dsse_sign( self::RECEIPT_TYPE, self::statement( self::AUTHORIZATION_PREDICATE, $head ), $key );
	}

	/** The signed receipt. `authorization` is the committed authorization with the log's answer, or null. */
	public static function receipt( array $head, array $execution, $authorization, $key ) {
		$predicate = $head + array(
			'session'   => array( 'id' => null, 'toolUseId' => null, 'provenance' => 'claimed' ),
			'model'     => array( 'id' => null, 'provenance' => 'claimed' ),
			'execution' => $execution,
		);
		if ( null !== $authorization ) {
			$predicate['authorization'] = $authorization;
		}
		return self::dsse_sign( self::RECEIPT_TYPE, self::statement( self::RECEIPT_PREDICATE, $predicate ), $key );
	}

	/** The outcome of a request that WordPress handled: the status it answered. */
	public static function answered( $status ) {
		$result = array( 'status' => (int) $status );
		return array( 'status' => $status >= 500 ? 'failed' : 'executed', 'result' => $result, 'resultDigest' => self::digest_of( $result ), 'provenance' => 'observed' );
	}
}
