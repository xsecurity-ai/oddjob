/**
 * Making a shell's output readable without rewriting it.
 *
 * A PTY — which is what `socat ...,pty` and most useful shells give
 * you — echoes what you type and prints a prompt after every
 * command. Stored faithfully, as it must be, a transcript then
 * reads:
 *
 *     $ whoami          <- what the operator typed, our record
 *     whoami            <- the PTY echoing it back
 *     brandon           <- the answer
 *     sh-3.2$           <- the prompt
 *
 * Two of those four lines are noise, and one of them (`␛[K`) is not
 * even text.
 *
 * **Nothing here changes what is stored.** The transcript is an
 * engagement record and a tidied version of it is not what
 * happened; this is a view over it, and the raw bytes stay one
 * toggle away. The rule is that cleaning may only ever REMOVE what
 * the terminal itself added — an echo of our own command, a control
 * sequence meant for a screen — and never anything the host said.
 */

/** CSI, OSC and the single-character escapes a shell emits.
 *
 *  Not a terminal emulator: this deletes the sequences rather than
 *  acting on them, which is right for a transcript and wrong for a
 *  live screen. A full-screen program over this still looks like
 *  nonsense, because it IS nonsense without a screen to paint. */
const ANSI = new RegExp(
  '\\u001B\\[[0-?]*[ -/]*[@-~]'      // CSI ... final byte
  + '|\\u001B\\][^\\u0007\\u001B]*(?:\\u0007|\\u001B\\\\)'  // OSC ... BEL/ST
  + '|\\u001B[@-Z\\\\-_]',           // two-character escapes
  'g')

/** Strip escape sequences and normalise line endings. */
export function clean(text: string): string {
  return text
    .replace(ANSI, '')
    // A PTY ends lines with CRLF. Left in, every line gains a
    // stray carriage return that renders as a blank.
    .replace(/\r\n/g, '\n')
    // A bare CR is a terminal overwriting the line it just drew --
    // a progress bar. Without a screen the useful part is what
    // came last, which is what keeping the tail does.
    .split('\n')
    .map((line) => (line.includes('\r')
      ? line.slice(line.lastIndexOf('\r') + 1) : line))
    .join('\n')
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
}

/**
 * Drop the shell's echo of the command we just sent.
 *
 * Only when the output's first line IS that command, exactly.
 * Anything looser would eat a line of real output that happened to
 * resemble what was typed — `grep whoami /etc/passwd` prints lines
 * containing the word, and losing the first would be losing
 * evidence.
 */
export function dropEcho(output: string, command: string | null): string {
  if (!command) return output
  const want = command.trim()
  if (!want) return output
  const nl = output.indexOf('\n')
  const first = (nl === -1 ? output : output.slice(0, nl)).trim()
  if (first !== want) return output
  return nl === -1 ? '' : output.slice(nl + 1)
}

/** What a transcript line shows, cleaned. */
export function render(output: string | null,
                       command: string | null): string {
  if (!output) return ''
  return dropEcho(clean(output), command)
}
