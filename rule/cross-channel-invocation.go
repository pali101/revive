package rule

import (
	"fmt"
	"go/ast"

	"github.com/mgechev/revive/lint"
)

type CrossChannelInvocation struct{}

// Apply applies the rule to the given file.
func (r *CrossChannelInvocation) Apply(file *lint.File, _ lint.Arguments) []lint.Failure {
	var failures []lint.Failure

	walker := lintCrossChannel{
		file: file,
		onFailure: func(failure lint.Failure) {
			failures = append(failures, failure)
		},
	}

	ast.Walk(walker, file.AST)

	return failures
}

// Name returns the rule name.
func (r *CrossChannelInvocation) Name() string {
	return "cross-channel-invocation"
}

type lintCrossChannel struct {
	file      *lint.File
	onFailure func(lint.Failure)
}

// Visit inspects AST nodes to detect cross-channel invocations.
func (w lintCrossChannel) Visit(node ast.Node) ast.Visitor {
	// Check if the node is a function call expression
	if callExpr, ok := node.(*ast.CallExpr); ok {
		// Check if the function being called is "InvokeChaincode"
		if selectorExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok && selectorExpr.Sel.Name == "InvokeChaincode" {
			// Verify there are three arguments and the third is a non-empty channel name
			if len(callExpr.Args) == 3 {
				// Check if the third argument is a non-empty channel string
				if arg, ok := callExpr.Args[2].(*ast.BasicLit); !ok || (ok && arg.Value != `""`) {
					channelName := "<unknown>"
					if ok {
						channelName = arg.Value
					}

					w.onFailure(lint.Failure{
						Confidence: 1,
						Node:       node,
						Failure: fmt.Sprintf(
							"Cross-channel invocation detected in function '%s'. Invoking 'InvokeChaincode' across channel '%s' may lead to data inconsistencies and potential security risks. "+
								"Ensure this cross-channel call is necessary, and validate the channel name '%s' to avoid unintended data access.",
							selectorExpr.Sel.Name, channelName, channelName),
						Category: "security",
					})
				}
			}
		}
	}

	return w
}
