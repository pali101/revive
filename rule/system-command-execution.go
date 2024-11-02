package rule

import (
	"fmt"
	"go/ast"

	"github.com/mgechev/revive/lint"
)

// SystemCommandRule detects the usage of system command executions, which can lead to nondeterminism.
type SystemCommandRule struct{}

// Apply applies the rule to the given file.
func (r *SystemCommandRule) Apply(file *lint.File, _ lint.Arguments) []lint.Failure {
	var failures []lint.Failure

	walker := lintSystemCommand{
		onFailure: func(failure lint.Failure) {
			failures = append(failures, failure)
		},
	}

	ast.Walk(walker, file.AST)

	return failures
}

// Name returns the rule name.
func (r *SystemCommandRule) Name() string {
	return "system-command-execution"
}

type lintSystemCommand struct {
	onFailure func(lint.Failure)
}

// Visit traverses the AST to detect calls to `exec.Command` or `exec.CommandContext`.
func (w lintSystemCommand) Visit(node ast.Node) ast.Visitor {
	// Look for function calls
	if callExpr, ok := node.(*ast.CallExpr); ok {
		if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
			// Check if the function being called is `Command` or `CommandContext`
			if selExpr.Sel.Name == "Command" || selExpr.Sel.Name == "CommandContext" {
				// Check if the package is `exec`
				if ident, ok := selExpr.X.(*ast.Ident); ok && ident.Name == "exec" {
					w.onFailure(lint.Failure{
						Confidence: 1,
						Failure:    fmt.Sprintf("System command execution detected using '%s.%s', which may lead to nondeterminism and security risks.", ident.Name, selExpr.Sel.Name),
						Node:       node,
						Category:   "security",
					})
				}
			}
		}
	}
	return w
}
