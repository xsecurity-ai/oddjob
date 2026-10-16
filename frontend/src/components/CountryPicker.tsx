/**
 * Which countries may be scanned. Used by the project and by each ghost.
 *
 * One component for both because they are the same control answering
 * two questions, and two copies of a safety control is how the two
 * stop agreeing. The wording differs; the behaviour must not.
 *
 * **Empty means everywhere.** That is the default for every project
 * and every ghost, and it is stated on the control rather than left
 * to be inferred from a blank box — "no countries selected" reads as
 * "nothing is allowed" to a reasonable person, and it means the
 * opposite.
 *
 * **Disabled without MaxMind.** The gate resolves a target's country
 * from a local GeoLite2 database. With no database there is no
 * country, so the control would be a setting that silently does
 * nothing. It is disabled and says why, with the place to fix it.
 */
import { Autocomplete, Box, Chip, TextField, Typography, alpha } from '@mui/material'
import PublicIcon from '@mui/icons-material/PublicOutlined'
import { neon } from '../theme'

/** ISO 3166-1 alpha-2, with the names MaxMind reports.
 *
 *  Not every country on earth: the ones an engagement plausibly
 *  touches, which keeps the list readable. A code MaxMind returns
 *  that is missing here still gates correctly — the gate compares
 *  codes and never consults this list — it simply shows as its bare
 *  code, which is why `freeSolo` is on. A picker that cannot express
 *  a country would be a picker that forces the restriction off. */
export const COUNTRIES: Array<{ code: string; name: string }> = [
  { code: 'AE', name: 'United Arab Emirates' }, { code: 'AR', name: 'Argentina' },
  { code: 'AT', name: 'Austria' }, { code: 'AU', name: 'Australia' },
  { code: 'BE', name: 'Belgium' }, { code: 'BR', name: 'Brazil' },
  { code: 'CA', name: 'Canada' }, { code: 'CH', name: 'Switzerland' },
  { code: 'CL', name: 'Chile' }, { code: 'CN', name: 'China' },
  { code: 'CZ', name: 'Czechia' }, { code: 'DE', name: 'Germany' },
  { code: 'DK', name: 'Denmark' }, { code: 'ES', name: 'Spain' },
  { code: 'FI', name: 'Finland' }, { code: 'FR', name: 'France' },
  { code: 'GB', name: 'United Kingdom' }, { code: 'HK', name: 'Hong Kong' },
  { code: 'ID', name: 'Indonesia' }, { code: 'IE', name: 'Ireland' },
  { code: 'IL', name: 'Israel' }, { code: 'IN', name: 'India' },
  { code: 'IT', name: 'Italy' }, { code: 'JP', name: 'Japan' },
  { code: 'KR', name: 'South Korea' }, { code: 'LU', name: 'Luxembourg' },
  { code: 'MX', name: 'Mexico' }, { code: 'MY', name: 'Malaysia' },
  { code: 'NL', name: 'Netherlands' }, { code: 'NO', name: 'Norway' },
  { code: 'NZ', name: 'New Zealand' }, { code: 'PH', name: 'Philippines' },
  { code: 'PL', name: 'Poland' }, { code: 'PT', name: 'Portugal' },
  { code: 'SE', name: 'Sweden' }, { code: 'SG', name: 'Singapore' },
  { code: 'TH', name: 'Thailand' }, { code: 'TR', name: 'Türkiye' },
  { code: 'TW', name: 'Taiwan' }, { code: 'US', name: 'United States' },
  { code: 'VN', name: 'Vietnam' }, { code: 'ZA', name: 'South Africa' },
]

const NAME = new Map(COUNTRIES.map((c) => [c.code, c.name]))

/** `"gb"` -> `"GB"`, and anything unusable -> null.
 *
 *  Exported because the test asserts it: a picker that lets `England`
 *  through sends a 422 the operator has to decode, and one that
 *  silently drops it loses a country they meant to add. */
export function normaliseCode(raw: string): string | null {
  const s = (raw || '').trim().toUpperCase()
  return /^[A-Z]{2}$/.test(s) ? s : null;
}

export function CountryPicker({
  value, onChange, available, label, help, disabled,
}: {
  value: string[]
  onChange: (next: string[]) => void
  /** False when geolocation is off or no database is installed. */
  available: boolean
  label: string
  help: string
  disabled?: boolean
}) {
  const off = !available || !!disabled
  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, mb: 0.5 }}>
        <PublicIcon fontSize="small"
          sx={{ color: off ? neon.muted : neon.cyan }} />
        <Typography sx={{ fontSize: 12.5, color: off ? neon.muted : neon.cyan }}>
          {label}
        </Typography>
      </Box>
      <Autocomplete
        multiple freeSolo disableCloseOnSelect disabled={off}
        options={COUNTRIES.map((c) => c.code)}
        value={value}
        getOptionLabel={(o) => (NAME.has(o) ? `${o} — ${NAME.get(o)}` : o)}
        onChange={(_e, next) => {
          // Normalise and de-duplicate here rather than on the way
          // out: `freeSolo` means the operator can type anything, and
          // the server answers a bad code with a 422 that reads like
          // a bug in the page.
          const out: string[] = []
          for (const raw of next as string[]) {
            const c = normaliseCode(raw)
            if (c && !out.includes(c)) out.push(c)
          }
          onChange(out.sort())
        }}
        renderValue={(vals, getProps) =>
          vals.map((v, i) => {
            const { key, ...rest } = getProps({ index: i })
            return <Chip key={key} {...rest} size="small" label={v}
              title={NAME.get(v) || v}
              sx={{ background: alpha(neon.cyan, 0.14), color: neon.cyan,
                    fontSize: 11.5 }} />
          })
        }
        renderInput={(params) => (
          <TextField {...params} size="small"
            placeholder={value.length ? '' : 'Everywhere'}
            sx={{ '& .MuiInputBase-root': { fontSize: 12.5 } }} />
        )}
      />
      <Typography sx={{ fontSize: 11.5, color: neon.muted, mt: 0.5 }}>
        {!available
          ? 'Needs MaxMind. Geolocation is off, or no GeoLite2 database '
            + 'has been downloaded — Settings → Site has the licence key, '
            + 'and Health has the download. Until then there is no country '
            + 'to check a target against, so this would do nothing.'
          : value.length === 0
            ? `Empty means everywhere. ${help}`
            : help}
      </Typography>
    </Box>
  );
}
