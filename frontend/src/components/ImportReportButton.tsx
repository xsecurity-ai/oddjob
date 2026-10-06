import { useState } from 'react'
import { Button, Tooltip, alpha } from '@mui/material'
import ScanIcon from '@mui/icons-material/DocumentScannerOutlined'
import { ImportScanDialog } from './ImportScanDialog'
import { neon } from '../theme'

/**
 * Import a scan, from wherever you are looking at its results.
 *
 * The same control on Targets, Services and Vulns rather than one
 * entry in the sidebar: importing is something you do *while* working
 * on a table, and the three views are all fed by the same reports.
 * Sending someone to a separate page and back loses their filters.
 *
 * It is one dialog and one endpoint; only the button is repeated.
 */
export function ImportReportButton({ project }: { project: string | null }) {
  const [open, setOpen] = useState(false)
  if (!project) {
    // An import has to land somewhere. Across all projects there is no
    // answer to "which one", and guessing puts a client's hosts in
    // another client's engagement.
    return (
      <Tooltip title="Pick a project to import into">
        <span>
          <Button size="small" variant="outlined" disabled
            startIcon={<ScanIcon sx={{ fontSize: 16 }} />}
            sx={{ fontSize: 11, py: 0.3 }}>
            Import report
          </Button>
        </span>
      </Tooltip>
    )
  }
  return (
    <>
      {open && (
        <ImportScanDialog project={project} onClose={() => setOpen(false)} />
      )}
      <Button size="small" variant="outlined"
        startIcon={<ScanIcon sx={{ fontSize: 16 }} />}
        onClick={() => setOpen(true)}
        sx={{ color: neon.cyan, borderColor: alpha(neon.cyan, 0.5),
              fontSize: 11, py: 0.3 }}>
        Import report
      </Button>
    </>
  )
}
