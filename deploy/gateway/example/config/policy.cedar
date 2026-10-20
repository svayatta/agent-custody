// Anyone whose grant names orders.get may read an order.
permit(principal, action == Action::"orders.get", resource);

// Refunds: only the support agent, only for an order the gateway itself looked up and found delivered, a positive
// amount that is never more than the order's total and never more than 500.00 (amounts are integer minor units).
// The gateway does not enforce a tool's inputSchema, so the policy has to bound the amount from below as well.
// context.facts.order is the answer of the gateway's own orders.get call; context.args is what the agent sent.
permit(principal == Agent::"support-agent", action == Action::"orders.refund", resource)
when {
  context.facts has order &&
  context.facts.order.status == "delivered" &&
  context.args.amount > 0 &&
  context.args.amount <= context.facts.order.total &&
  context.args.amount <= 50000
};
