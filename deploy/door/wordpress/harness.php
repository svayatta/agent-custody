<?php
// The test suite calls the door class through this file. It reads calls as JSON on stdin and writes each result as
// JSON on stdout. It is not in the plugin zip.
//
// A call is { "fn": name, "args": [...] }. For a function that makes an HTTP request, the call gives the answer:
// "http": { "status": 200, "body": "..." }, or "http": { "error": "..." } for no answer. The result has the request
// that the function made.
require __DIR__ . '/agent-custody-door/includes/class-agent-custody-door.php';

// JSON objects become PHP arrays, but an empty object stays an object: an empty PHP array is a JSON list.
function harness_arrays( $v ) {
	if ( $v instanceof stdClass ) {
		$v = (array) $v;
		if ( ! $v ) {
			return new stdClass();
		}
	}
	return is_array( $v ) ? array_map( 'harness_arrays', $v ) : $v;
}

$out = array();
foreach ( harness_arrays( json_decode( stream_get_contents( STDIN ) ) ) as $call ) {
	$requests = array();
	$args     = $call['args'];
	if ( isset( $call['http'] ) ) {
		$canned = $call['http'];
		$args[] = function ( $method, $url, $headers, $body ) use ( $canned, &$requests ) {
			$requests[] = compact( 'method', 'url', 'headers', 'body' );
			if ( isset( $canned['error'] ) ) {
				throw new RuntimeException( $canned['error'] );
			}
			return array( $canned['status'], $canned['body'] );
		};
	}
	try {
		$out[] = array( 'result' => call_user_func_array( array( 'Agent_Custody_Door', $call['fn'] ), $args ), 'requests' => $requests );
	} catch ( Exception $e ) {
		$out[] = array( 'error' => $e->getMessage(), 'requests' => $requests );
	}
}
echo json_encode( $out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
