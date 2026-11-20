// Anyone may read the catalogue. A refund is for a verified agent, of at most 5000 minor units: this door relays, so it
// reads the JSON body. Every other arrival is denied (Cedar denies by default).
permit(principal, action == Action::"catalogue", resource);

permit(principal, action == Action::"refund", resource)
when {
  context.facts.arrival.class == "verified" &&
  context.args has body && context.args.body has amount && context.args.body.amount <= 5000
};
