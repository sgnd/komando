package term

// VTOK: the terminal on stderr reads escape sequences (colour, clearing a
// line). Only an old Windows console does not.
var VTOK = true
