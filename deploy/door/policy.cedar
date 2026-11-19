// The door sees the request line and headers, never the body: a rule here can read who arrived and where they are
// going, not the amount of a refund. Rules on the body belong at the origin, or in a door that relays (no authz).
permit(principal, action == Action::"catalogue", resource);

permit(principal, action == Action::"refund", resource)
when { context.facts.arrival.class == "verified" };
