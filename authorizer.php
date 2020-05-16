<?php

/*
Class to validate JWT token provided by a reverse proxy downstream.

Intended to be used as a companion of the deployment of 
traefik-forward-auth, app-identity-and-access-adapter or similar.

Author: Mario Hros
Repo: https://github.com/k3a/jwt-authorizer
License: 3-clause BSD

Using https://github.com/lcobucci/jwt/blob/3.3/README.md for JWT ops (3-clause BSD)
Some parts based on https://github.com/okta/okta-jwt-verifier-php (Apache 2.0)
*/

require __DIR__ . '/vendor/autoload.php';

use Lcobucci\JWT\Parser;
use Lcobucci\Jose\Parsing;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;

class JWTAuthVerifier
{
    const USER_NAME_COOKIE = "_admin_auth_user_name";
    const TOKEN_HEADER_NAME = "Authorization";
    const JWKS_CACHE_TTL = 60; // 0 to disable

    private $allowedIssuerDomains;
	private $tokenVerified = false;
	private $groups = null;

	public $userName = "Unknown";

    private static function fail($str)
	{
        die("Authentication failed: $str");
    }

    /**
     * Constructor
     * @param array $allowedIssuers list of allowed issuer domains (domain part of iss claim), e.g. auth.domain.com
     * @param string $jwtInput (optional) JWT input string to verify (will use Authentication header if not provided)
     */
    public function __construct($allowedIssuerDomains, $jwtInput = null)
    {
        if (is_null($jwtInput) || strlen($jwtInput) == 0) {
            $heads = getallheaders();
            if ($heads === false) {
                self::fail("unable to get request headers and no token provided directly");
                return;
            }

            // attempt to extract JWT from Authorization header
            foreach($heads as $h => $v) {
                if (strcasecmp($h, self::TOKEN_HEADER_NAME) == 0) {
					$varr = explode(" ", $v);
					if (count($varr) == 0) {
						// empty array of space-separated items, skip
						continue;
					}
					if (count($varr) == 2 && strcasecmp($varr[0], "Bearer") == 0) {
						// looks like bearer token, stop here and return the second part
						$jwtInput = $varr[1];
						break;
					} else if ($bearerToken == "") {
						// our best bet so far...
						$jwtInput = $varr[0];
					}
                }
            }
        }

        $this->allowedIssuerDomains = $allowedIssuerDomains;

        if (strlen($jwtInput) > 0) {
            try {
                $this->token = (new Parser())->parse($jwtInput);
                if ($this->token === false) {
                    self::fail("unable to parse token");
                    return;
                }
            } catch(Exception $e) {
                $this->token = null;
                return;
            }

            $cookieUserName = isset($_COOKIE[self::USER_NAME_COOKIE]) ? trim($_COOKIE[self::USER_NAME_COOKIE], '"') : "";
            
			if ($cookieUserName != "") {
				$this->userName = $cookieUserName;
			} else {
				$email = $this->token->getClaim("email");
				if (!is_null($email) && $email != "") {
					$this->userName = $email;
				}
			}
		}
    }

	/**
	 * Returns a boolean indicating whether a bearer token was provided.
	 * CAUTION: This does not check the validity of the token, use verify() for that!
	 */
	public function hasToken()
	{
		return $this->token != null && $this->token !== false;
	}

    /**
     * Case-insensitive comparison of group names with special handling of email group format as follows:
     * Groups "test" and "test@domain.com" are considered the same, whereas 
     * "test@company.com" and "test@domain.com" are considered different.
     */
    private static function groupNamesEqual($grp1, $grp2)
    {
        // exact match
        if (strlen($grp1) > 0 && strcasecmp($grp1, $grp2) == 0) {
            return true;
        }

        // split email format to "username" and "domain" parts
        $grp1 = explode("@", $grp1);
        if ($grp1 === false) {
            return false;
        }
        $grp2 = explode("@", $grp2);
        if ($grp2 === false) {
            return false;
        }

        // check different number of elements (this is required to prevent matching different domains!)
        if ((count($grp1) == 1 && count($grp2) > 1) || (count($grp1) > 1 && count($grp2) == 1)) {
            // extract "username" part before @ and make sure it is not empty
            $grp1 = $grp1[0];
            if (strlen($grp1) == 0) {
                return false;
            }
            $grp2 = $grp2[0];
            if (strlen($grp2) == 0) {
                return false;
            }

            // just do the case-insensitive compare of those "username" parts
            return strcasecmp($grp1, $grp2) == 0;
        }

        return false;
    }

    /**
     * Downloads fresh keys from the OIDC provider URL $iss.
     * Returns an array of keys or FALSE
     */
    private static function downloadKeysFromIssuer($iss)
    {
        if ($iss == "") {
            return false;
        }

		$url = "$iss/.well-known/openid-configuration";
		$oidc_conf = file_get_contents($url);
		if ($oidc_conf === false) {
			self::fail("OIDC configuration at $url unreachable");
			return false;
		}

		$oidc_conf = json_decode($oidc_conf, true);
		if ($oidc_conf === false) {
			self::fail("OIDC configuration at $url invalid");
			return false;
		}

		$jwks_uri = $oidc_conf["jwks_uri"];
		if (is_null($jwks_uri) || $jwks_uri == "") {
			self::fail("OIDC configuration at $url doesn't specify jwks_uri");
			return false;
		}

		$keys = file_get_contents($jwks_uri);
		if ($keys === false) {
			self::fail("JWKS URI $jwks_uri unreachable");
			return false;
		}

		$keys = json_decode($keys, true);
		if ($keys === false) {
			self::fail("JWKS URI $jwks_uri invalid");
			return false;
		}

		$keys = $keys["keys"];
		if ($keys === false) {
			self::fail("JWKS URI $jwks_uri doesn't specify keys");
			return false;
		}

        return $keys;
    }

    /**
     * Attempts to find $kid in the list of keys and returns it's PEM representation 
     * Returns FALSE if the supported key was not found or conversion to PEM failed
     */
    private static function getPemKeyFromKeys($kid, $keys) 
    {
		foreach ($keys as $k) {
			if ($k["kid"] == $kid) {
				$kty = $k["kty"];
				if ($kty == "RSA") {
					return self::createPemFromModulusAndExponent($k["n"], $k["e"]);
				} else {
					self::fail("JWKS URI $jwks_uri provides unsupported key type $kty for key $kid");
					return false;
				}
			}
        }
        return false;
    }

    /**
     * Gets the PEM-formatted key $kid from the OIDC provider URL $iss.
     * Cache may be used (if configured) to avoid downloading the key for every request.
     */
    private static function getPemKeyFromIssuer($iss, $kid)
    {
        $cachePath = "";

        if ($iss == "" || $kid == "") {
            return false;
        }

        if (self::JWKS_CACHE_TTL > 0) {
            $cachePath = sys_get_temp_dir() . "/" . hash("md5", $iss);
            if (file_exists($cachePath)) {
                $j = json_decode(file_get_contents($cachePath), true);

                // if cache file decoded ok..
                if ($j !== false && !is_null($j) && isset($j["ts"])) {
                    $age = time() - $j["ts"];
                    // and cache is not too old
                    if ($age < self::JWKS_CACHE_TTL) {
                        $pem = self::getPemKeyFromKeys($kid, $j["keys"]);
                        // and pem key can be get
                        if (isset($pem) && $pem != "") {
                            // return key from the cache
                            return $pem;
                        }
                    }
                }
            }
        }

        // download fresh keys
        $keys = self::downloadKeysFromIssuer($iss);
        if ($keys === false) {
            return false;
        }

        // attempt to get PEM from the list of keys
        $pem = self::getPemKeyFromKeys($kid, $keys);
        if (!isset($pem) || $pem === false || $pem == "") {
            return false;
        }

        // cache if possible
        if (self::JWKS_CACHE_TTL > 0) {
            $obj = [
                "keys" => $keys,
                "ts" => time(),
            ];
            
            $jstr = json_encode($obj);

            file_put_contents($cachePath, $jstr);
        }
        
        return $pem;
    }

	/**
	 * Verifies a valid token has been provided, signed with a whitelisted issuer
	 */
    public function verify()
    {
        // check we have a token first
        if (!$this->hasToken()) {
            self::fail("no valid parsed token");
            return false;
        }

		// already verified?
		if ($this->tokenVerified) {
			return true;
		}

        $iss = $this->token->getClaim("iss");
        if (is_null($iss) || $iss == "") {
            self::fail("no iss (issuer) claim in the token");
            return false;
        }

        $headers = $this->token->getHeaders();
        if (is_null($headers)) {
            self::fail("no headers provided in the parsed token");
            return false;
        }

        $alg = $headers["alg"];
        if (is_null($alg) || $alg == "") {
            self::fail("no alg in the token header");
            return false;
        }

        $kid = $headers["kid"];
        if (is_null($kid) || $kid == "") {
            self::fail("no kid in the token header");
            return false;
        }

        $pemPublicKey = self::getPemKeyFromIssuer($iss, $kid);
        if ($pemPublicKey === false) {
            self::fail("issuer $iss doesn't provide key $kid");
            return false;
        }

        $signer = null;

        if ($alg == "RS256") {
            $signer = new Sha256();
        } else {
            self::fail("token alg $alg not supported");
            return false;
        }

        $this->tokenVerified = $this->token->verify($signer, new Key($pemPublicKey));

		return $this->tokenVerified;
    }

	/**
	 * getGroups validates the token and extracts group
	 */
	public function getGroups()
	{
		if (!is_null($this->groups)) {
			return $this->groups;
		}

        if (!$this->verify()) {
            return false;
        }

        $groups = $this->token->getClaim("groups");
        if (is_null($groups) || !is_array($groups)) {
            self::fail("groups claim is not an array");
            return false;
        }

		$this->groups = $groups;
		return $this->groups;
	}

	/**
	  * Maps user groups from the token to the array of new groups using the mapping dict mapDict.
	  * Keys in mapDict can be groups names, emails or email part before '@'.
	  * mapDict can be null, in which case all groups are used.
	  * If stripDomains is true, character '@' and following are stripped from the final group names.
	  */
	public function mapGroups($mapDict = null, $stripDomains = false) 
	{
        $groups = $this->getGroups();
        if ($groups === false) {
            return false;
        }

		$finalGroups = [];
		foreach($groups as $grp) {
			$key = "";
			if (is_null($mapDict)) {
				// use key directly
				$key = $grp;
			} else {
				// use the value of the mapDict if the key matches
				foreach($mapDict as $mdk => $mdv) {
					if (self::groupNamesEqual($grp, $mdk)) {
						$key = $mdv;
					}
				}
			}

			// this key should not be emitted
			if ($key == "") {
				continue;
			}

			// stip domain part if asked
			if ($stripDomains) {
				$arr = explode("@", $key);
				$key = $arr[0];
			}

			$finalGroups[] = $key;
		}

		return $finalGroups;
	}

	/**
	 * Verifies a valid token has been provided, signed with a whitelisted issuer and containing the provided group name
	 */
    public function verifyGroup($groupName)
    {
		if (!$this->verify()) {
			return false;
		}

		$groups = $this->getGroups();
		if ($groups === false) {
			return false;
		}

        foreach($groups as $grp) {
            if (self::groupNamesEqual($grp, $groupName)) {
                return true;
            }
        }

        return false;
    }

    /**
     * DER-encode the length
     *
     * DER supports lengths up to (2**8)**127, however, we'll only support lengths up to (2**8)**4.  See
     * {@link http://itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#p=13 X.690 paragraph 8.1.3} for more information.
     *
     * @access private
     * @param int $length
     * @return string
     */
    private static function encodeLength($length)
    {
        if ($length <= 0x7F) {
            return chr($length);
        }

        $temp = ltrim(pack('N', $length), chr(0));
        return pack('Ca*', 0x80 | strlen($temp), $temp);
    }

    /**
     *
     * Create a public key represented in PEM format from RSA modulus and exponent information
     *
     * @param string $n the RSA modulus encoded in Base64
     * @param string $e the RSA exponent encoded in Base64
     * @return string the RSA public key represented in PEM format
     */
    private static function createPemFromModulusAndExponent($n, $e)
    {
		if (is_null($n) || is_null($e) || $n == "" || $e == "") {
			return false;
		}

		$decoder = new \Lcobucci\JWT\Parsing\Decoder();

        $modulus = $decoder->base64UrlDecode($n);
        $publicExponent = $decoder->base64UrlDecode($e);


        $components = array(
            'modulus' => pack('Ca*a*', 2, self::encodeLength(strlen($modulus)), $modulus),
            'publicExponent' => pack('Ca*a*', 2, self::encodeLength(strlen($publicExponent)), $publicExponent)
        );

        $RSAPublicKey = pack(
            'Ca*a*a*',
            48,
            self::encodeLength(strlen($components['modulus']) + strlen($components['publicExponent'])),
            $components['modulus'],
            $components['publicExponent']
        );


        // sequence(oid(1.2.840.113549.1.1.1), null)) = rsaEncryption.
        $rsaOID = pack('H*', '300d06092a864886f70d0101010500'); // hex version of MA0GCSqGSIb3DQEBAQUA
        $RSAPublicKey = chr(0) . $RSAPublicKey;
        $RSAPublicKey = chr(3) . self::encodeLength(strlen($RSAPublicKey)) . $RSAPublicKey;

        $RSAPublicKey = pack(
            'Ca*a*',
            48,
            self::encodeLength(strlen($rsaOID . $RSAPublicKey)),
            $rsaOID . $RSAPublicKey
        );

        $RSAPublicKey = "-----BEGIN PUBLIC KEY-----\r\n" .
            chunk_split(base64_encode($RSAPublicKey), 64) .
            '-----END PUBLIC KEY-----';

        return $RSAPublicKey;
    }
}