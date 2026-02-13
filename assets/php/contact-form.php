<?php

	// CSRF-Token prüfen
	session_start();
	if (!isset($_POST['csrf_token']) || !isset($_SESSION['csrf_token']) || 
	    !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
		http_response_code(403);
		echo('error: invalid token');
		exit;
	}

	// Rate Limiting (einfach über Session)
	if (isset($_SESSION['last_contact_time']) && (time() - $_SESSION['last_contact_time']) < 60) {
		http_response_code(429);
		echo('error: too many requests');
		exit;
	}

	// Honeypot-Feld prüfen (Spam-Schutz)
	if (!empty($_POST['website'])) {
		// Bot erkannt
		http_response_code(200);
		echo('success');
		exit;
	}

	$name = trim($_POST['name'] ?? '');
	$email = trim($_POST['email'] ?? '');
	$message = trim($_POST['message'] ?? '');

	// Eingabevalidierung
	if (empty($name) || empty($email) || empty($message)) {
		http_response_code(400);
		echo('error: missing fields');
		exit;
	}

	// E-Mail validieren
	if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
		http_response_code(400);
		echo('error: invalid email');
		exit;
	}

	// Eingaben bereinigen gegen Header-Injection
	$name = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
	$name = str_replace(array("\r", "\n"), '', $name);
	$email = str_replace(array("\r", "\n"), '', $email);
	$message = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');

	$emailTo = 'pkostelnik@snat.tech';
	$subject = 'Kontaktaufnahme ueber meine Webseite';
	$body = "Name: $name \n\nEmail: $email \n\nMessage:\n$message";
	$headers = 'From: noreply@snat.tech' . "\r\n" .
	           'Reply-To: ' . $email . "\r\n" .
	           'Content-Type: text/plain; charset=UTF-8' . "\r\n";

	mail($emailTo, $subject, $body, $headers);
	$_SESSION['last_contact_time'] = time();
	echo('success');
	
?>
