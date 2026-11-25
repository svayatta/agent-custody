// A verified agent with a registry passport, on the store's "agents" admission list, may place an order, and may
// refund a positive amount of at most 50000 minor units (500.00 in a currency with two decimals). Anything else is refused.
permit(principal, action == Action::"order", resource)
when {
  context.facts.arrival.class == "verified" &&
  context.facts.arrival has passport &&
  context.facts.arrival.passport.outcome == "verified" &&
  context.facts.arrival has admission &&
  context.facts.arrival.admission.lists.contains("agents")
};

permit(principal, action == Action::"refund", resource)
when {
  context.facts.arrival.class == "verified" &&
  context.facts.arrival has passport &&
  context.facts.arrival.passport.outcome == "verified" &&
  context.facts.arrival has admission &&
  context.facts.arrival.admission.lists.contains("agents") &&
  context.args.body.amount > 0 &&
  context.args.body.amount <= 50000
};
