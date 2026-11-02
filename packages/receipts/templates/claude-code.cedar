// Starter policy for `agent-custody init claude-code`.
// The policy permits every call and forbids a short list of destructive Bash commands.
// A pattern matches the text of the command. It is not a sandbox: it catches the plain form of each command.
// Each rule has a `@reason`. The hook shows it to the agent and to the person who reads the session.
// The `like` operator is case-sensitive, so each SQL keyword has a rule for each case.
permit(principal, action, resource);

// Rewriting shared history.
@reason("force push rewrites shared history")
forbid(principal, action == Action::"Bash", resource)
when { context.args has command && context.args.command like "*git push*--force*" };

@reason("force push rewrites shared history")
forbid(principal, action == Action::"Bash", resource)
when { context.args has command && context.args.command like "*git push*-f *" };

@reason("force push rewrites shared history")
forbid(principal, action == Action::"Bash", resource)
when { context.args has command && context.args.command like "*git push*-f" };

// Deleting the root directory or the home directory.
@reason("rm -rf on the root directory")
forbid(principal, action == Action::"Bash", resource)
when { context.args has command && (context.args.command like "*rm -rf /" || context.args.command like "*rm -rf / *" || context.args.command like "*rm -rf /\*") };

@reason("rm -rf on the home directory")
forbid(principal, action == Action::"Bash", resource)
when { context.args has command && (context.args.command like "*rm -rf ~" || context.args.command like "*rm -rf ~ *" || context.args.command like "*rm -rf ~/" || context.args.command like "*rm -rf ~/ *" || context.args.command like "*rm -rf ~/\*") };

// Destroying infrastructure or a database.
@reason("terraform destroy deletes infrastructure")
forbid(principal, action == Action::"Bash", resource)
when { context.args has command && context.args.command like "*terraform destroy*" };

@reason("drop database deletes a database")
forbid(principal, action == Action::"Bash", resource)
when { context.args has command && context.args.command like "*drop database*" };

@reason("drop database deletes a database")
forbid(principal, action == Action::"Bash", resource)
when { context.args has command && context.args.command like "*DROP DATABASE*" };
