package rule

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/mgechev/revive/lint"
)

// ImportsBlocklistRule lints given else constructs.
type ImportsBlocklistRule struct {
	blocklist []*regexp.Regexp
	sync.Mutex
}

var replaceImportRegexp = regexp.MustCompile(`/?\*\*/?`)

// Default blocklist specific to chaincode
var defaultChaincodeBlocklist = []string{"time", "math/rand", "net", "os"}

func (r *ImportsBlocklistRule) configure(arguments lint.Arguments) {
	r.Lock()
	defer r.Unlock()

	if r.blocklist == nil {
		r.blocklist = make([]*regexp.Regexp, 0)

		// Determine if custom arguments are provided; if not, use the default chaincode specific blocklist
		if len(arguments) > 0 {
			for _, arg := range arguments {
				argStr, ok := arg.(string)
				if !ok {
					panic(fmt.Sprintf("Invalid argument to the imports-blocklist rule. Expecting a string, got %T", arg))
				}
				regStr, err := regexp.Compile(fmt.Sprintf(`(?m)"%s"$`, replaceImportRegexp.ReplaceAllString(argStr, `(\W|\w)*`)))
				if err != nil {
					panic(fmt.Sprintf("Invalid argument to the imports-blocklist rule. Expecting %q to be a valid regular expression, got: %v", argStr, err))
				}
				r.blocklist = append(r.blocklist, regStr)
			}
		} else {
			// No arguments, so add default chaincode blocklist
			for _, item := range defaultChaincodeBlocklist {
				regStr := regexp.MustCompile(fmt.Sprintf(`(?m)"%s"$`, replaceImportRegexp.ReplaceAllString(item, `(\W|\w)*`)))
				r.blocklist = append(r.blocklist, regStr)
			}
		}
	}
}

func (r *ImportsBlocklistRule) isBlocklisted(path string) bool {
	for _, regex := range r.blocklist {
		// Skip "fabric" imports even if they match blocklist entries
		if regex.MatchString(path) && !strings.Contains(path, "fabric") {
			return true
		}
	}
	return false
}

// Apply applies the rule to given file.
func (r *ImportsBlocklistRule) Apply(file *lint.File, arguments lint.Arguments) []lint.Failure {
	r.configure(arguments)

	var failures []lint.Failure

	for _, is := range file.AST.Imports {
		path := is.Path
		if path != nil && r.isBlocklisted(path.Value) {
			failures = append(failures, lint.Failure{
				Confidence: 1,
				Failure:    fmt.Sprintf("blocklisted import %s used; consider removing it due to policy (e.g., nondeterminism, security risk)", path.Value),
				Node:       is,
				Category:   "imports",
			})
		}
	}

	return failures
}

// Name returns the rule name.
func (*ImportsBlocklistRule) Name() string {
	return "imports-blocklist"
}
