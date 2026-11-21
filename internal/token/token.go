package token

import (
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/gatework/netops/config"
	"github.com/gatework/netops/parse"
)

// Words is one statement split on white space, with double-quoted words
// kept whole and unquoted.
type Words []string

// Split splits text into words.
func Split(text string) Words {
	var out Words
	for text = strings.TrimSpace(text); text != ""; text = strings.TrimLeft(text, " \t") {
		if text[0] == '"' {
			if end := strings.IndexByte(text[1:], '"'); end >= 0 {
				out = append(out, text[1:end+1])
				text = text[end+2:]
				continue
			}
		}
		end := strings.IndexAny(text, " \t")
		if end < 0 {
			end = len(text)
		}
		out = append(out, text[:end])
		text = text[end:]
	}
	return out
}

// At returns word i, or "" when out of range.
func (w Words) At(i int) string {
	if i < 0 || i >= len(w) {
		return ""
	}
	return w[i]
}

// Has reports whether keyword is one of the words.
func (w Words) Has(keyword string) bool { return slices.Contains(w, keyword) }

// Prefix reports whether the statement starts with the given words.
func (w Words) Prefix(words ...string) bool {
	return len(w) >= len(words) && slices.Equal(w[:len(words)], words)
}

// After returns the word that follows the first occurrence of keyword.
func (w Words) After(keyword string) (string, bool) {
	i := slices.Index(w, keyword)
	if i < 0 || i+1 >= len(w) {
		return "", false
	}
	return w[i+1], true
}

// Int returns the integer that follows keyword, or 0.
func (w Words) Int(keyword string) int {
	v, ok := w.After(keyword)
	if !ok {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return n
}

// From returns the words from index i on.
func (w Words) From(i int) Words {
	if i >= len(w) {
		return nil
	}
	return w[i:]
}

var keywordPattern = regexp.MustCompile(`^[a-z][a-z0-9+-]*[a-z+]$`)

// Keyword returns the leading keywords of a statement, to aggregate
// statements an extractor could not decode without leaking values: at most
// two words for a top-level statement and one inside a block or on a line
// the dialect deems sensitive, stopping at the first word that is not a
// lowercase keyword.
func Keyword(n *parse.Node, d config.Dialect) string {
	limit := 1
	if n.Depth == 0 && !d.SensitiveLine(n.Text) {
		limit = 2
	}
	out := make([]string, 0, limit)
	for _, s := range Split(n.Text) {
		if len(out) == limit || !keywordPattern.MatchString(s) {
			break
		}
		out = append(out, s)
	}
	return strings.Join(out, " ")
}
