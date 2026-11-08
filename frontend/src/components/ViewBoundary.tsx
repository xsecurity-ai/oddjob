/**
 * What a view does when its code will not load.
 *
 * Before the views were split into chunks this could not happen: the
 * whole application arrived in one file, and if that file loaded then
 * every screen in it worked. Splitting bought a 42% smaller first
 * load and introduced one new way to fail — a chunk fetched on
 * navigation can be missing — so this is the other half of that
 * change rather than a general-purpose safety net.
 *
 * **The common cause is a deploy, not a network fault.** Chunk names
 * carry a content hash. A tab left open across a release is holding
 * an `index.html` that names files the server no longer has, so the
 * next view it opens 404s. Reloading fetches the new index and the
 * new names, which is why the button says what it does.
 *
 * A class component because that is still the only way to catch a
 * render error in React. `Suspense` handles the waiting; this handles
 * the not-arriving, and the two are different events.
 */
import { Component, type ErrorInfo, type ReactNode } from 'react'
import { Alert, AlertTitle, Box, Button, Stack } from '@mui/material'
import RefreshIcon from '@mui/icons-material/Refresh'

type Props = { children: ReactNode; onReset?: () => void }
type State = { error: Error | null }

export class ViewBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // To the console and no further. There is no error-reporting
    // service here, and inventing one that posts a client's stack
    // traces somewhere is not a decision this component gets to make.
    console.error('view failed to render', error, info.componentStack)
  }

  render() {
    const { error } = this.state
    if (!error) return this.props.children

    // A failed dynamic import, as opposed to a bug in the view. The
    // message differs between browsers, so this matches loosely and
    // treats the ambiguous case as the ordinary one.
    const chunk = /dynamically imported module|Importing a module script failed|Failed to fetch/i
      .test(`${error.message}`)

    return (
      <Box sx={{ flex: 1, display: 'flex', alignItems: 'center',
                 justifyContent: 'center', p: 4 }}>
        <Alert severity="warning" variant="outlined" sx={{ maxWidth: 560 }}>
          <AlertTitle sx={{ fontSize: 13 }}>
            {chunk ? 'This page could not be loaded'
                   : 'This page stopped working'}
          </AlertTitle>
          <Stack spacing={1.5}>
            <Box sx={{ fontSize: 12.5, lineHeight: 1.7 }}>
              {chunk
                ? 'Its code could not be fetched. The usual reason is that '
                  + 'Oddjob was updated while this tab was open, so the files '
                  + 'this page is asking for have been replaced. Reloading '
                  + 'picks up the new ones.'
                : 'Something in it raised an error. Nothing was saved or '
                  + 'changed by the failure, and the rest of the application '
                  + 'is still usable.'}
            </Box>
            <Box sx={{ fontSize: 11, opacity: 0.75,
                       fontFamily: `'Share Tech Mono', monospace`,
                       wordBreak: 'break-word' }}>
              {String(error.message).slice(0, 300)}
            </Box>
            <Stack direction="row" spacing={1}>
              <Button size="small" variant="outlined"
                startIcon={<RefreshIcon fontSize="small" />}
                onClick={() => window.location.reload()}
                sx={{ textTransform: 'none' }}>Reload</Button>
              {/* Clearing the error without reloading is worth
                  offering for a view that merely threw: the rest of
                  the app is fine and a reload costs every cached
                  query. It is not offered for a missing chunk,
                  because retrying the same import fetches the same
                  missing file. */}
              {!chunk && (
                <Button size="small"
                  onClick={() => {
                    this.setState({ error: null })
                    this.props.onReset?.()
                  }}
                  sx={{ textTransform: 'none' }}>Try again</Button>
              )}
            </Stack>
          </Stack>
        </Alert>
      </Box>
    )
  }
}
