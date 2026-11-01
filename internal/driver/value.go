package driver

import (
	"encoding/base64"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"
)

// JSONValue converts a value from a database, cache or bucket into something JSON keeps exactly:
// text stays text, binary becomes {"base64": ...}, times become RFC 3339,
// and integers too large for a JSON number become strings.
func JSONValue(v any) any {
	switch x := v.(type) {
	case nil, bool, string:
		return x
	case []byte:
		if utf8.Valid(x) && !strings.ContainsRune(string(x), 0) {
			return string(x)
		}
		return map[string]string{"base64": base64.StdEncoding.EncodeToString(x)}
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	case int64:
		if x > 1<<53 || x < -(1<<53) {
			return fmt.Sprint(x)
		}
		return x
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return fmt.Sprint(x)
		}
		return x
	case int, int32, int16, int8, uint8, uint16, uint32, float32:
		return x
	case uint64:
		if x > 1<<53 {
			return fmt.Sprint(x)
		}
		return x
	}
	return fmt.Sprint(v)
}
