package rule

import (
	"go/ast"

	"github.com/mgechev/revive/lint"
)

// GoroutinesRule detects the use of goroutines
type ConcurrencyGoRoutinesRule struct{}

// Apply applies the rule to the given file.
func (r *ConcurrencyGoRoutinesRule) Apply(file *lint.File, _ lint.Arguments) []lint.Failure {
	var failures []lint.Failure

	fileAst := file.AST
	walker := lintGoRoutines{
		file:    file,
		fileAst: fileAst,
		onFailure: func(failure lint.Failure) {
			failures = append(failures, failure)
		},
	}

	ast.Walk(walker, fileAst)

	return failures
}

// Name returns the rule name.
func (r *ConcurrencyGoRoutinesRule) Name() string {
	return "concurrency-go-routines"
}

type lintGoRoutines struct {
	file      *lint.File
	fileAst   *ast.File
	onFailure func(lint.Failure)
}

// Visit traverses the AST to detect goroutines
func (w lintGoRoutines) Visit(node ast.Node) ast.Visitor {
	switch n := node.(type) {
	case *ast.GoStmt:
		funcName := findEnclosingFunction(w.fileAst, n)
		message := "should not use goroutines, will lead to non-deterministic behaviour"
		if funcName != "" {
			message += " in function: " + funcName
		}

		w.onFailure(lint.Failure{
			Confidence: 1,
			Failure:    message,
			Node:       n,
			Category:   "goroutines",
		})
		return w
	}
	return w
}

// findEnclosingFunction finds the name of the function that encloses a given AST node, if any.
func findEnclosingFunction(fileAst *ast.File, node ast.Node) string {
	var funcName string

	ast.Inspect(fileAst, func(n ast.Node) bool {
		if fn, ok := n.(*ast.FuncDecl); ok {
			if fn.Pos() <= node.Pos() && fn.End() >= node.End() {
				funcName = fn.Name.Name
				return false
			}
		}
		return true
	})

	return funcName
}
