// An ACS Guardian's policy. The action and the resource are the tool name; context.args holds the argument values the
// agent submitted (or, for a result, exit_status and outputs); context.acs.method names the hook.

@reason("reading a published report is allowed")
permit (principal, action == Action::"file_read", resource)
when {
  context.acs.method == "steps/toolCallRequest" &&
  context.args has path &&
  context.args.path like "/reports/*"
};

@reason("a result may reach the agent only for a request this Guardian allowed")
permit (principal, action == Action::"file_read", resource)
when {
  context.acs.method == "steps/toolCallResult" &&
  context.acs has requestRef &&
  context.acs.requestRef has decision &&
  context.acs.requestRef.decision == "allow"
};
