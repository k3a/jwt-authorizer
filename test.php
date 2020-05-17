<pre>
<?php

require('./authorizer.php');

//echo "oik";
print_r(getallheaders());

//htmlspecialchars($_COOKIE["name"])

$jav = new JWTAuthVerifier(["admin-auth.ndemiccreations.com"], "some-key");

$user_name = $jav->userName;
echo "User Name: $user_name\n";

if (!$jav->hasToken()) {
	echo "No token provided!";
} else {
	$gok = $jav->verifyGroup("team");
	echo "Group ok: ".($gok?"y":"n")."\n";

	$grps = $jav->getGroups();
	echo "Groups:\n";
	print_r($grps);

	echo "Mapped groups (nil + strip):\n";
	$mgrps = $jav->mapGroups(null, true);
	print_r($mgrps);

	echo "Mapped groups:\n";
	$mgrps = $jav->mapGroups([
			"team" => "employee",
		], true);
	print_r($mgrps);
}
