package rule

import (
	"fmt"
	"go/ast"
	"go/token"

	"github.com/mgechev/revive/lint"
)

// GlobalScopeCheckRule detects global state variables
type GlobalScopeCheckRule struct{}

// Apply applies the rule to the given file.
func (r *GlobalScopeCheckRule) Apply(file *lint.File, _ lint.Arguments) []lint.Failure {
	var failures []lint.Failure

	// Initialize a walker to traverse the AST
	walker := &lintGlobalScopeCheck{
		onFailure: func(failure lint.Failure) {
			failures = append(failures, failure)
		},
	}

	// Walk through the AST and apply the rule
	ast.Walk(walker, file.AST)

	return failures
}

// Name returns the rule name.
func (r *GlobalScopeCheckRule) Name() string {
	return "global-scope-check"
}

// lintGlobalScopeCheck is an AST visitor that identifies global variables
type lintGlobalScopeCheck struct {
	onFailure func(lint.Failure)
}

// Visit method is called for each AST node during traversal
func (w *lintGlobalScopeCheck) Visit(node ast.Node) ast.Visitor {
	// Only look for global (top-level) variable declarations
	if decl, ok := node.(*ast.GenDecl); ok && decl.Tok == token.VAR {
		for _, spec := range decl.Specs {
			if valueSpec, ok := spec.(*ast.ValueSpec); ok {
				for _, name := range valueSpec.Names {
					// Report failure for each global variable found
					w.onFailure(lint.Failure{
						Confidence: 1,
						Failure:    fmt.Sprintf("global variable detected: %s; using global variables may lead to non-deterministic behavior", name),
						Node:       node,
						Category:   "variables",
					})
				}
			}
		}
	}

	// Continue traversal
	return w
}
