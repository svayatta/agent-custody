<?php
/**
 * Plugin Name:       Agent Custody Door
 * Plugin URI:        https://agent-custody.dev/
 * Description:       Protects comments and forms. The door decides each submission with a policy preset, and signs a receipt of each decision that anyone can verify.
 * Version:           0.1.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            Svayatta Forge
 * Author URI:        https://svayattaforge.com/
 * License:           Apache-2.0
 * License URI:       https://www.apache.org/licenses/LICENSE-2.0
 * Text Domain:       agent-custody-door
 */

defined( 'ABSPATH' ) || exit;

require_once __DIR__ . '/includes/class-agent-custody-door.php';

const ACD_OPTION     = 'agent_custody_door';
const ACD_KEY_OPTION = 'agent_custody_door_key';
const ACD_CRON       = 'agent_custody_door_flush';
// The requests to the log and to the challenge provider are made while a visitor waits.
const ACD_HTTP_TIMEOUT = 5;

function acd_table() {
	global $wpdb;
	return $wpdb->prefix . 'agent_custody_receipts';
}

/** The settings. A secret in wp-config.php (`AGENT_CUSTODY_DOOR_LOG_TOKEN`, `AGENT_CUSTODY_DOOR_CHALLENGE_SECRET`) replaces the stored one. */
function acd_settings() {
	$s = wp_parse_args(
		(array) get_option( ACD_OPTION, array() ),
		array(
			'log_url'   => '',
			'log_token' => '',
			'log_keys'  => array(),
			'preset'    => 'watch',
			'provider'  => 'turnstile',
			'site_key'  => '',
			'secret'    => '',
			'hostnames' => '',
			'protect'   => Agent_Custody_Door::ROUTES,
			'paths'     => '',
		)
	);
	if ( defined( 'AGENT_CUSTODY_DOOR_LOG_TOKEN' ) ) {
		$s['log_token'] = AGENT_CUSTODY_DOOR_LOG_TOKEN;
	}
	if ( defined( 'AGENT_CUSTODY_DOOR_CHALLENGE_SECRET' ) ) {
		$s['secret'] = AGENT_CUSTODY_DOOR_CHALLENGE_SECRET;
	}
	return $s;
}

/** The door does nothing until it has a log and the log's keys. */
function acd_connected( array $s ) {
	return '' !== $s['log_url'] && ! empty( $s['log_keys'] ) && get_option( ACD_KEY_OPTION );
}

function acd_log( array $s ) {
	return array( 'url' => $s['log_url'], 'token' => $s['log_token'], 'keys' => $s['log_keys'] );
}

/** The challenge config, or null when the site key or the secret is not set. */
function acd_challenge( array $s ) {
	if ( '' === $s['site_key'] || '' === $s['secret'] ) {
		return null;
	}
	$hosts = array_filter( array_map( 'trim', explode( ',', strtolower( $s['hostnames'] ) ) ) );
	if ( ! $hosts ) {
		$hosts = array( strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) ) );
	}
	return array( 'provider' => $s['provider'], 'siteKey' => $s['site_key'], 'secret' => $s['secret'], 'hostnames' => array_values( $hosts ) );
}

function acd_paths( array $s ) {
	return array_values( array_filter( array_map( 'trim', explode( "\n", $s['paths'] ) ) ) );
}

/** HTTP for the door class. A redirect is not followed: it would send the token or the secret to another host. */
function acd_http( $method, $url, array $headers, $body ) {
	$res = wp_remote_request(
		$url,
		array( 'method' => $method, 'headers' => $headers, 'body' => $body, 'timeout' => ACD_HTTP_TIMEOUT, 'redirection' => 0 )
	);
	if ( is_wp_error( $res ) ) {
		throw new RuntimeException( $res->get_error_message() );
	}
	return array( (int) wp_remote_retrieve_response_code( $res ), wp_remote_retrieve_body( $res ) );
}

// ---- install ----

register_activation_hook(
	__FILE__,
	function () {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta(
			'CREATE TABLE ' . acd_table() . " (
			receipt_id varchar(64) NOT NULL,
			created datetime NOT NULL,
			route varchar(32) NOT NULL,
			class varchar(16) NOT NULL,
			decision varchar(8) NOT NULL,
			status varchar(16) NOT NULL,
			bundle longtext NOT NULL,
			PRIMARY KEY  (receipt_id),
			KEY status_created (status, created)
			) " . $wpdb->get_charset_collate() . ';'
		);
		// The signing key stays on this site. Deactivation and removal keep it and the receipts: they are the evidence.
		if ( ! get_option( ACD_KEY_OPTION ) ) {
			add_option( ACD_KEY_OPTION, Agent_Custody_Door::new_key(), '', false );
		}
		if ( ! wp_next_scheduled( ACD_CRON ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', ACD_CRON );
		}
	}
);

register_deactivation_hook(
	__FILE__,
	function () {
		wp_clear_scheduled_hook( ACD_CRON );
	}
);

// ---- receipts ----

function acd_store( $receipt_id, array $head, $status, array $bundle ) {
	global $wpdb;
	$wpdb->replace(
		acd_table(),
		array(
			'receipt_id' => $receipt_id,
			'created'    => gmdate( 'Y-m-d H:i:s' ),
			'route'      => $head['tool']['name'],
			'class'      => $head['facts']['arrival']['value']['class'],
			'decision'   => $head['policy']['decision'],
			'status'     => $status,
			'bundle'     => wp_json_encode( $bundle, JSON_UNESCAPED_SLASHES ),
		)
	);
}

/** Appends a signed receipt to the log and stores the bundle. A receipt that the log does not take stays `pending`. */
function acd_send( $receipt_id, array $envelope, array $s ) {
	global $wpdb;
	try {
		$answer = Agent_Custody_Door::append( $envelope, acd_log( $s ), 'acd_http' );
	} catch ( Exception $e ) {
		error_log( 'agent-custody door: receipt ' . $receipt_id . ' is not in the log yet: ' . $e->getMessage() );
		return false;
	}
	$wpdb->update(
		acd_table(),
		array( 'status' => 'logged', 'bundle' => wp_json_encode( array( 'envelope' => $envelope ) + $answer, JSON_UNESCAPED_SLASHES ) ),
		array( 'receipt_id' => $receipt_id )
	);
	return true;
}

/** Signs the receipt, stores it as `pending`, and returns the envelope. */
function acd_record( array $head, array $execution, $authorization ) {
	$envelope = Agent_Custody_Door::receipt( $head, $execution, $authorization, get_option( ACD_KEY_OPTION ) );
	acd_store( $head['receiptId'], $head, 'pending', array( 'envelope' => $envelope ) );
	return $envelope;
}

add_action(
	ACD_CRON,
	function () {
		global $wpdb;
		$s = acd_settings();
		if ( ! acd_connected( $s ) ) {
			return;
		}
		// ponytail: 50 receipts an hour, oldest first. A site under a long attack needs a shorter schedule or a batch append.
		foreach ( $wpdb->get_results( 'SELECT receipt_id, bundle FROM ' . acd_table() . " WHERE status = 'pending' ORDER BY created LIMIT 50" ) as $row ) {
			$bundle = json_decode( $row->bundle, true );
			if ( ! isset( $bundle['envelope'] ) || ! acd_send( $row->receipt_id, $bundle['envelope'], $s ) ) {
				break;
			}
		}
		$days = (int) apply_filters( 'agent_custody_door_retention_days', 90 );
		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . acd_table() . " WHERE status = 'logged' AND created < %s", gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS ) ) );
	}
);

// ---- the gate ----

function acd_request_headers() {
	$headers = array();
	foreach ( $_SERVER as $name => $value ) {
		if ( is_string( $value ) && 0 === strpos( $name, 'HTTP_' ) ) {
			$headers[ strtolower( str_replace( '_', '-', substr( $name, 5 ) ) ) ] = $value;
		}
	}
	if ( ! empty( $_SERVER['CONTENT_TYPE'] ) ) {
		$headers['content-type'] = (string) $_SERVER['CONTENT_TYPE'];
	}
	return $headers;
}

function acd_refuse( $status, array $head, $message ) {
	if ( ! headers_sent() ) {
		header( 'X-Agent-Custody-Receipt: ' . $head['receiptId'] );
		header( 'X-Agent-Custody-Class: ' . $head['facts']['arrival']['value']['class'] );
	}
	wp_die(
		esc_html( $message ) . ' ' . esc_html( sprintf( /* translators: %s: receipt id */ __( 'Receipt: %s', 'agent-custody-door' ), $head['receiptId'] ) ),
		esc_html__( 'Not accepted', 'agent-custody-door' ),
		array( 'response' => (int) $status, 'back_link' => true )
	);
}

add_action(
	'init',
	function () {
		global $pagenow;
		if ( 'POST' !== ( isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : '' ) ) {
			return;
		}
		// The way back in for an owner whom the door locked out: `define( 'AGENT_CUSTODY_DOOR_OFF', true );` in wp-config.php.
		if ( defined( 'AGENT_CUSTODY_DOOR_OFF' ) && AGENT_CUSTODY_DOOR_OFF ) {
			return;
		}
		$s = acd_settings();
		if ( ! acd_connected( $s ) ) {
			return;
		}
		$path = (string) wp_parse_url( isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '/', PHP_URL_PATH );
		// phpcs:ignore WordPress.Security.NonceVerification -- the door reads which form this is; it changes nothing itself.
		$action = isset( $_REQUEST['action'] ) && is_string( $_REQUEST['action'] ) ? $_REQUEST['action'] : '';
		$route  = Agent_Custody_Door::route( (string) $pagenow, $action, $path, (array) $s['protect'], acd_paths( $s ) );
		if ( null === $route ) {
			return;
		}
		$key       = get_option( ACD_KEY_OPTION );
		$headers   = acd_request_headers();
		$challenge = acd_challenge( $s );
		$outcome   = null;
		if ( $challenge ) {
			$field = Agent_Custody_Door::TOKEN_FIELD[ $challenge['provider'] ];
			// phpcs:ignore WordPress.Security.NonceVerification -- the token is checked with the provider.
			$token   = isset( $_POST[ $field ] ) && is_string( $_POST[ $field ] ) ? wp_unslash( $_POST[ $field ] ) : ( isset( $headers[ Agent_Custody_Door::CHALLENGE_HEADER ] ) ? $headers[ Agent_Custody_Door::CHALLENGE_HEADER ] : '' );
			$outcome = Agent_Custody_Door::check_challenge( $challenge, $token, 'acd_http' );
		}
		$arrival = Agent_Custody_Door::arrival( $headers, isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '', 'POST', $path, $route, $outcome );
		$d       = Agent_Custody_Door::decide( $key, $s['preset'], $arrival, $headers, is_user_logged_in() );
		$head    = $d['head'];
		$watch   = isset( $head['policy']['enforced'] );

		if ( ! $d['forward'] ) {
			$envelope = acd_record( $head, $d['denied'], null );
			register_shutdown_function( 'acd_finish', $head['receiptId'], $envelope, $s );
			acd_refuse( 403, $head, $challenge ? __( 'This form needs the challenge. Go back, complete the challenge, and send the form again.', 'agent-custody-door' ) : __( 'This form does not accept this request.', 'agent-custody-door' ) );
		}

		// The decision is in the log before WordPress acts on the request. If the log does not take it, the request stops here.
		$authorization = null;
		try {
			$envelope      = Agent_Custody_Door::authorization( $head, $key );
			$authorization = array( 'envelope' => $envelope ) + Agent_Custody_Door::append( $envelope, acd_log( $s ), 'acd_http' );
			acd_store( $head['receiptId'], $head, 'authorized', $authorization );
		} catch ( Exception $e ) {
			if ( ! $watch ) {
				$execution = array( 'status' => 'withheld', 'reason' => 'the log did not commit the authorization, so WordPress did not get the request: ' . $e->getMessage(), 'provenance' => 'observed' );
				$envelope  = acd_record( $head, $execution, null );
				register_shutdown_function( 'acd_finish', $head['receiptId'], $envelope, $s );
				acd_refuse( 503, $head, __( 'The form could not be recorded, so it was not sent. Try again in a minute.', 'agent-custody-door' ) );
			}
			error_log( 'agent-custody door (watch): the log did not commit the authorization for receipt ' . $head['receiptId'] . ': ' . $e->getMessage() );
		}
		if ( ! headers_sent() ) {
			header( 'X-Agent-Custody-Receipt: ' . $head['receiptId'] );
			header( 'X-Agent-Custody-Class: ' . $arrival['class'] );
		}
		register_shutdown_function(
			function () use ( $head, $authorization, $s ) {
				$envelope = acd_record( $head, Agent_Custody_Door::answered( http_response_code() ), $authorization );
				acd_finish( $head['receiptId'], $envelope, $s );
			}
		);
	},
	1
);

/** At shutdown: the visitor has the answer before the receipt goes to the log. */
function acd_finish( $receipt_id, array $envelope, array $s ) {
	if ( function_exists( 'fastcgi_finish_request' ) ) {
		fastcgi_finish_request();
	}
	acd_send( $receipt_id, $envelope, $s );
}

// ---- the challenge widget ----

/** The widget for a protected form, or an empty string when this visitor needs none. */
function acd_widget( $route ) {
	$s         = acd_settings();
	$challenge = acd_challenge( $s );
	if ( ! $challenge || ! acd_connected( $s ) || ( 'form' !== $route && ! in_array( $route, (array) $s['protect'], true ) ) || ( 'strict' !== $s['preset'] && is_user_logged_in() ) ) {
		return '';
	}
	$turnstile = 'turnstile' === $challenge['provider'];
	wp_enqueue_script( 'agent-custody-door-challenge', $turnstile ? 'https://challenges.cloudflare.com/turnstile/v0/api.js' : 'https://js.hcaptcha.com/1/api.js', array(), null, true ); // phpcs:ignore WordPress.WP.EnqueuedResourceParameters -- the provider's script has no version.
	return '<div class="' . ( $turnstile ? 'cf-turnstile' : 'h-captcha' ) . '" data-sitekey="' . esc_attr( $challenge['siteKey'] ) . '"></div>';
}

add_filter(
	'comment_form_submit_field',
	function ( $field ) {
		return acd_widget( 'comment' ) . $field;
	}
);
foreach ( array( 'login_form' => 'login', 'register_form' => 'register', 'lostpassword_form' => 'lostpassword' ) as $acd_hook => $acd_route ) {
	add_action(
		$acd_hook,
		function () use ( $acd_route ) {
			echo acd_widget( $acd_route ); // phpcs:ignore WordPress.Security.EscapeOutput -- built from escaped parts.
		}
	);
}
// With extra paths, each form on the page that posts to this site gets the widget, so its token goes with the fields.
add_action(
	'wp_footer',
	function () {
		if ( ! acd_paths( acd_settings() ) ) {
			return;
		}
		$widget = acd_widget( 'form' );
		if ( '' === $widget ) {
			return;
		}
		?>
<script>
document.querySelectorAll('form').forEach(function (f) {
	if (f.method !== 'post' || new URL(f.action, location.href).origin !== location.origin || f.querySelector('.cf-turnstile, .h-captcha')) return;
	var d = document.createElement('div');
	d.innerHTML = <?php echo wp_json_encode( $widget ); ?>;
	var b = f.querySelector('[type=submit]');
	if (b && b.parentNode) b.parentNode.insertBefore(d, b); else f.appendChild(d);
});
</script>
		<?php
	},
	5
);

// ---- settings ----

add_action(
	'admin_init',
	function () {
		register_setting( ACD_OPTION, ACD_OPTION, array( 'sanitize_callback' => 'acd_sanitize' ) );
	}
);

function acd_sanitize( $in ) {
	// WordPress calls this a second time, with the result of the first, when it adds the option.
	static $clean = null;
	if ( null === $clean || $in !== $clean ) {
		$clean = acd_clean( $in );
	}
	return $clean;
}

/** The settings form as the stored option. With a new log URL, it reads and pins the log's keys. */
function acd_clean( $in ) {
	$old = (array) get_option( ACD_OPTION, array() ) + array( 'log_url' => '', 'log_token' => '', 'log_keys' => array(), 'secret' => '' );
	$in  = (array) $in;
	$get = function ( $name ) use ( $in ) {
		return isset( $in[ $name ] ) && is_string( $in[ $name ] ) ? trim( $in[ $name ] ) : '';
	};
	$out = array(
		'log_url'   => esc_url_raw( $get( 'log_url' ), array( 'https', 'http' ) ),
		// An empty secret field keeps the stored secret: the form never shows it.
		'log_token' => '' !== $get( 'log_token' ) ? $get( 'log_token' ) : $old['log_token'],
		'secret'    => '' !== $get( 'secret' ) ? $get( 'secret' ) : $old['secret'],
		'preset'    => array_key_exists( $get( 'preset' ), Agent_Custody_Door::presets() ) ? $get( 'preset' ) : 'watch',
		'provider'  => 'hcaptcha' === $get( 'provider' ) ? 'hcaptcha' : 'turnstile',
		'site_key'  => sanitize_text_field( $get( 'site_key' ) ),
		'hostnames' => sanitize_text_field( $get( 'hostnames' ) ),
		'protect'   => array_values( array_intersect( Agent_Custody_Door::ROUTES, isset( $in['protect'] ) ? (array) $in['protect'] : array() ) ),
		'paths'     => sanitize_textarea_field( $get( 'paths' ) ),
		'log_keys'  => array(),
	);
	if ( '' === $out['log_url'] ) {
		return $out;
	}
	// The log's keys are pinned when the site connects. A log at a new URL is a new log.
	if ( $out['log_url'] === $old['log_url'] && $old['log_keys'] ) {
		$out['log_keys'] = $old['log_keys'];
		return $out;
	}
	$local = defined( 'AGENT_CUSTODY_DOOR_ALLOW_HTTP' ) && AGENT_CUSTODY_DOOR_ALLOW_HTTP;
	try {
		if ( 'https' !== wp_parse_url( $out['log_url'], PHP_URL_SCHEME ) && ! $local ) {
			throw new RuntimeException( __( 'the log URL must start with https://', 'agent-custody-door' ) );
		}
		$origin              = preg_replace( '#^(https?://[^/]+).*$#', '$1', $out['log_url'] );
		list( $status, $doc ) = acd_http( 'GET', $origin . '/.well-known/agent-custody-log.json', array(), null );
		if ( 200 !== $status ) {
			throw new RuntimeException( sprintf( 'the log serves no key document (%d)', $status ) );
		}
		$out['log_keys'] = Agent_Custody_Door::parse_log_keys( $doc );
	} catch ( Exception $e ) {
		add_settings_error( ACD_OPTION, 'acd_log', sprintf( /* translators: %s: reason */ __( 'Not connected to the log: %s', 'agent-custody-door' ), $e->getMessage() ) );
	}
	return $out;
}

add_action(
	'admin_menu',
	function () {
		add_options_page( __( 'Agent Custody Door', 'agent-custody-door' ), __( 'Agent Custody Door', 'agent-custody-door' ), 'manage_options', 'agent-custody-door', 'acd_page' );
	}
);

add_action(
	'admin_notices',
	function () {
		if ( current_user_can( 'manage_options' ) && ! acd_connected( acd_settings() ) ) {
			echo '<div class="notice notice-warning"><p>' . wp_kses_post( sprintf( /* translators: %s: settings URL */ __( 'Agent Custody Door protects nothing until it is <a href="%s">connected to a log</a>.', 'agent-custody-door' ), esc_url( admin_url( 'options-general.php?page=agent-custody-door' ) ) ) ) . '</p></div>';
		}
	}
);

// A receipt bundle as a file, for `agent-custody verify`.
add_action(
	'admin_post_agent_custody_door_receipt',
	function () {
		global $wpdb;
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Not allowed.', 'agent-custody-door' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'agent_custody_door_receipt' );
		$id     = isset( $_GET['id'] ) ? sanitize_text_field( wp_unslash( $_GET['id'] ) ) : '';
		$bundle = $wpdb->get_var( $wpdb->prepare( 'SELECT bundle FROM ' . acd_table() . ' WHERE receipt_id = %s', $id ) );
		if ( null === $bundle ) {
			wp_die( esc_html__( 'No such receipt.', 'agent-custody-door' ), '', array( 'response' => 404 ) );
		}
		header( 'Content-Type: application/json' );
		header( 'Content-Disposition: attachment; filename="' . sanitize_file_name( $id ) . '.json"' );
		echo $bundle; // phpcs:ignore WordPress.Security.EscapeOutput -- JSON that this plugin wrote, sent as a file.
		exit;
	}
);

function acd_page() {
	global $wpdb;
	$s      = acd_settings();
	$key    = get_option( ACD_KEY_OPTION );
	$name   = function ( $field ) {
		return esc_attr( ACD_OPTION . '[' . $field . ']' );
	};
	$labels = array(
		'watch'  => __( 'Watch: record what Humans decides, and refuse nothing. Start here.', 'agent-custody-door' ),
		'humans' => __( 'Humans: a visitor must pass the challenge. A signed-in user needs no challenge.', 'agent-custody-door' ),
		'strict' => __( 'Strict: each submission must pass the challenge, also from a signed-in user.', 'agent-custody-door' ),
	);
	$forms  = array(
		'comment'      => __( 'Comments', 'agent-custody-door' ),
		'login'        => __( 'Login', 'agent-custody-door' ),
		'register'     => __( 'Registration', 'agent-custody-door' ),
		'lostpassword' => __( 'Lost password', 'agent-custody-door' ),
	);
	?>
<div class="wrap">
<h1><?php esc_html_e( 'Agent Custody Door', 'agent-custody-door' ); ?></h1>
<form method="post" action="options.php">
	<?php settings_fields( ACD_OPTION ); ?>
<table class="form-table" role="presentation">
<tr><th scope="row"><label for="acd-log-url"><?php esc_html_e( 'Log URL', 'agent-custody-door' ); ?></label></th><td>
	<input id="acd-log-url" class="regular-text code" type="url" name="<?php echo $name( 'log_url' ); ?>" value="<?php echo esc_attr( $s['log_url'] ); ?>" placeholder="https://log.agent-custody.dev/t/YOUR-TENANT/">
	<p class="description"><?php echo $s['log_keys'] ? esc_html( sprintf( /* translators: %s: key ids */ __( 'Connected. Pinned log keys: %s', 'agent-custody-door' ), implode( ', ', array_map( function ( $k ) { return substr( $k, 0, 12 ); }, array_keys( $s['log_keys'] ) ) ) ) ) : esc_html__( 'Not connected. The door protects nothing.', 'agent-custody-door' ); ?></p></td></tr>
<tr><th scope="row"><label for="acd-log-token"><?php esc_html_e( 'Log token', 'agent-custody-door' ); ?></label></th><td>
	<input id="acd-log-token" class="regular-text" type="password" autocomplete="off" name="<?php echo $name( 'log_token' ); ?>" value="" placeholder="<?php echo '' !== $s['log_token'] ? esc_attr__( '(set; leave empty to keep it)', 'agent-custody-door' ) : ''; ?>"></td></tr>
<tr><th scope="row"><?php esc_html_e( 'Policy preset', 'agent-custody-door' ); ?></th><td><fieldset>
	<?php foreach ( $labels as $preset => $label ) : ?>
	<label><input type="radio" name="<?php echo $name( 'preset' ); ?>" value="<?php echo esc_attr( $preset ); ?>" <?php checked( $s['preset'], $preset ); ?>> <?php echo esc_html( $label ); ?></label><br>
	<?php endforeach; ?>
	</fieldset></td></tr>
<tr><th scope="row"><?php esc_html_e( 'Protected forms', 'agent-custody-door' ); ?></th><td><fieldset>
	<?php foreach ( $forms as $route => $label ) : ?>
	<label><input type="checkbox" name="<?php echo $name( 'protect' ); ?>[]" value="<?php echo esc_attr( $route ); ?>" <?php checked( in_array( $route, (array) $s['protect'], true ) ); ?>> <?php echo esc_html( $label ); ?></label><br>
	<?php endforeach; ?>
	</fieldset></td></tr>
<tr><th scope="row"><label for="acd-paths"><?php esc_html_e( 'More protected paths', 'agent-custody-door' ); ?></label></th><td>
	<textarea id="acd-paths" class="large-text code" rows="3" name="<?php echo $name( 'paths' ); ?>" placeholder="/wp-json/contact-form-7/*"><?php echo esc_textarea( $s['paths'] ); ?></textarea>
	<p class="description"><?php esc_html_e( 'One path on each line, exact or with /* at the end. The door decides each POST to these paths.', 'agent-custody-door' ); ?></p></td></tr>
<tr><th scope="row"><label for="acd-provider"><?php esc_html_e( 'Challenge', 'agent-custody-door' ); ?></label></th><td>
	<select id="acd-provider" name="<?php echo $name( 'provider' ); ?>">
		<option value="turnstile" <?php selected( $s['provider'], 'turnstile' ); ?>>Cloudflare Turnstile</option>
		<option value="hcaptcha" <?php selected( $s['provider'], 'hcaptcha' ); ?>>hCaptcha</option>
	</select></td></tr>
<tr><th scope="row"><label for="acd-site-key"><?php esc_html_e( 'Challenge site key', 'agent-custody-door' ); ?></label></th><td>
	<input id="acd-site-key" class="regular-text code" type="text" name="<?php echo $name( 'site_key' ); ?>" value="<?php echo esc_attr( $s['site_key'] ); ?>"></td></tr>
<tr><th scope="row"><label for="acd-secret"><?php esc_html_e( 'Challenge secret', 'agent-custody-door' ); ?></label></th><td>
	<input id="acd-secret" class="regular-text" type="password" autocomplete="off" name="<?php echo $name( 'secret' ); ?>" value="" placeholder="<?php echo '' !== $s['secret'] ? esc_attr__( '(set; leave empty to keep it)', 'agent-custody-door' ) : ''; ?>"></td></tr>
<tr><th scope="row"><label for="acd-hostnames"><?php esc_html_e( 'Challenge hostnames', 'agent-custody-door' ); ?></label></th><td>
	<input id="acd-hostnames" class="regular-text code" type="text" name="<?php echo $name( 'hostnames' ); ?>" value="<?php echo esc_attr( $s['hostnames'] ); ?>" placeholder="<?php echo esc_attr( (string) wp_parse_url( home_url(), PHP_URL_HOST ) ); ?>">
	<p class="description"><?php esc_html_e( 'The hostnames of the pages that show the challenge, with commas between them. Empty: the hostname of this site.', 'agent-custody-door' ); ?></p></td></tr>
</table>
	<?php submit_button(); ?>
</form>

<h2><?php esc_html_e( 'The key of this door', 'agent-custody-door' ); ?></h2>
<p><?php esc_html_e( 'The door signs each receipt with a key that stays on this site. Give this public key to a person who verifies a receipt.', 'agent-custody-door' ); ?></p>
<textarea class="large-text code" rows="3" readonly><?php echo esc_textarea( $key ? Agent_Custody_Door::public_pem( $key ) : '' ); ?></textarea>
<p><code>agent-custody verify RECEIPT.json --issuer-key door.pub --log-url <?php echo esc_html( '' !== $s['log_url'] ? $s['log_url'] : 'LOG-URL' ); ?></code></p>

<h2><?php esc_html_e( 'The last 20 decisions', 'agent-custody-door' ); ?></h2>
<table class="widefat striped"><thead><tr>
	<th><?php esc_html_e( 'Time (UTC)', 'agent-custody-door' ); ?></th><th><?php esc_html_e( 'Form', 'agent-custody-door' ); ?></th><th><?php esc_html_e( 'Arrival', 'agent-custody-door' ); ?></th><th><?php esc_html_e( 'Decision', 'agent-custody-door' ); ?></th><th><?php esc_html_e( 'Log', 'agent-custody-door' ); ?></th><th><?php esc_html_e( 'Receipt', 'agent-custody-door' ); ?></th>
</tr></thead><tbody>
	<?php foreach ( $wpdb->get_results( 'SELECT receipt_id, created, route, class, decision, status FROM ' . acd_table() . ' ORDER BY created DESC LIMIT 20' ) as $row ) : ?>
<tr><td><?php echo esc_html( $row->created ); ?></td><td><?php echo esc_html( $row->route ); ?></td><td><?php echo esc_html( $row->class ); ?></td><td><?php echo esc_html( $row->decision ); ?></td><td><?php echo esc_html( $row->status ); ?></td>
	<td><a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=agent_custody_door_receipt&id=' . rawurlencode( $row->receipt_id ) ), 'agent_custody_door_receipt' ) ); ?>"><code><?php echo esc_html( $row->receipt_id ); ?></code></a></td></tr>
	<?php endforeach; ?>
</tbody></table>
</div>
	<?php
}
