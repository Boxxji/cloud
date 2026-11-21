// Package text shapes strings for the wire: Cut and Trim bound a value without
// splitting a character, Unix and Time render an instant as RFC 3339 with "" for
// an unset one, and Plain turns what a program printed into text a reader can take.
//
// Plain exists because a run's narration is a terminal's output — `dev` colours
// its log lines, a build draws progress with carriage returns — and it is read far
// from any terminal: as JSON by every client of the session log, as mrkdwn in a
// Slack thread. There an escape sequence is not colour, it is noise, and a raw
// control character is worse: a JSON reader is required to refuse one ("control
// characters from U+0000 through U+001F must be escaped"), so one ESC in one log
// line made a whole session unreadable. What the line SAID survives the trip; how
// the terminal was asked to draw it does not.
package text
