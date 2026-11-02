// Starter policy for `agent-custody init claude-code`.
// The policy permits every call and forbids a short list of destructive Bash commands.
// A pattern matches the text of the command. It is not a sandbox: it catches the plain form of each command.
// The `like` operator is case-sensitive, so each SQL keyword has a rule for each case.
permit(principal, action, resource);

// Rewriting shared history.
forbid(principal, action == Action::"Bash", resource)
when { context.args has command && context.args.command like "*git push*--force*" };

forbid(principal, action == Action::"Bash", resource)
when { context.args has command && context.args.command like "*git push*-f *" };

forbid(principal, action == Action::"Bash", resource)
when { context.args has command && context.args.command like "*git push*-f" };

// Deleting the root directory or the home directory.
forbid(principal, action == Action::"Bash", resource)
when { context.args has command && (context.args.command like "*rm -rf /" || context.args.command like "*rm -rf / *" || context.args.command like "*rm -rf /\*") };

forbid(principal, action == Action::"Bash", resource)
when { context.args has command && (context.args.command like "*rm -rf ~" || context.args.command like "*rm -rf ~ *" || context.args.command like "*rm -rf ~/" || context.args.command like "*rm -rf ~/ *" || context.args.command like "*rm -rf ~/\*") };

// Destroying infrastructure or a database.
forbid(principal, action == Action::"Bash", resource)
when { context.args has command && context.args.command like "*terraform destroy*" };

forbid(principal, action == Action::"Bash", resource)
when { context.args has command && context.args.command like "*drop database*" };

forbid(principal, action == Action::"Bash", resource)
when { context.args has command && context.args.command like "*DROP DATABASE*" };
