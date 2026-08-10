import { useEffect, useState } from 'react'
import { DPoPService } from '../services/dpopService'
import { OAuthService } from '../services/oauthService'
import { getOAuthSettings } from '../config/oauth'
import {
  DPOP_FAULTS,
  expectedStatus,
  faultGroups,
  findFault,
  type DpopFault,
  type DpopFaultKey,
} from '../services/dpopFaults'

interface SuiteRow {
  fault: DpopFault
  status: number
  error?: string
  description?: string
  passed: boolean
}

/**
 * Arms a single deliberate DPoP fault for the next request, so the server's rejection paths can be
 * exercised from the existing buttons elsewhere in the app.
 *
 * One fault at a time on purpose: with two active the server stops at whichever check runs first, so
 * the response would no longer say anything about the scenario that was picked.
 */
export function DpopFaultInjector() {
  const dpop = DPoPService.getInstance()
  const [armed, setArmed] = useState<DpopFaultKey | null>(dpop.getArmedFault())
  const [rows, setRows] = useState<SuiteRow[] | null>(null)
  const [running, setRunning] = useState(false)
  const [baselineError, setBaselineError] = useState<string | null>(null)

  useEffect(() => dpop.onArmedFaultChange(setArmed), [])

  const armedFault = armed ? findFault(armed) : undefined

  /**
   * Runs every scenario that applies to a resource call, one at a time.
   *
   * Resource calls rather than the token endpoint: they are repeatable, whereas each token request
   * would need a fresh authorization code. It drives the same armed-fault path the manual switches
   * use, so the suite tests what actually happens rather than a parallel code path.
   */
  const runSuite = async () => {
    const oauth = OAuthService.getInstance()
    const url = getOAuthSettings().protectedResource
    setRunning(true)
    setRows(null)
    setBaselineError(null)

    try {
      // Without this a suite in which everything fails looks exactly like a suite that works. If a
      // clean call cannot succeed, every "correctly rejected" below would be meaningless.
      dpop.armFault(null)
      const baseline = await oauth.fetchResource(url, 'GET')
      if (!baseline.ok) {
        setBaselineError(
          `A clean request already fails with HTTP ${baseline.status}. Fix that first: until it succeeds, the results below prove nothing.`
        )
        return
      }

      const collected: SuiteRow[] = []
      for (const fault of DPOP_FAULTS.filter((f) => f.targets.includes('rs'))) {
        // Some scenarios build on the request before them. Everything up to this point was rejected,
        // and a rejected proof records nothing, so without a clean request in between the reuse would
        // send an identifier the server has never seen and be accepted for the right reason.
        if (fault.requiresAcceptedPredecessor) {
          dpop.armFault(null)
          await oauth.fetchResource(url, 'GET')
        }

        dpop.armFault(fault.key)
        const response = await oauth.fetchResource(url, 'GET')
        const body = await response.json().catch(() => null)
        // Where the error lives depends on who answers. A protected resource puts it in the
        // WWW-Authenticate challenge and leaves the body empty (RFC 9449 section 7.1); the token
        // endpoint puts it in the body. The proxy may hand that body back nested. Accept all three.
        const challenge = response.headers.get('www-authenticate') ?? ''
        const error: string | undefined =
          body?.error ?? body?.body?.error ?? challengeParam(challenge, 'error')
        const description: string | undefined =
          body?.error_description ??
          body?.body?.error_description ??
          challengeParam(challenge, 'error_description')

        collected.push({
          fault,
          status: response.status,
          error,
          description,
          // Status and error only, as agreed. The description is shown but never judged, because it
          // is prose that may be reworded without the behaviour changing.
          passed: response.status === expectedStatus('rs') && error === fault.expectedError,
        })
        setRows([...collected])
      }
    } finally {
      // Never leave a fault behind: the next thing anyone does would fail for reasons they did not
      // choose, and this runs even when a request throws.
      dpop.armFault(null)
      setRunning(false)
    }
  }

  return (
    <div className="mt-4">
      <h2 className="text-lg font-medium text-gray-900">Deliberate DPoP faults</h2>
      <p className="mt-1 text-sm text-gray-600">
        Arm one scenario, then use the normal buttons in this app to send the request. The fault
        stays armed until you disarm it, and survives a page reload. While a fault is armed the
        automatic nonce retry is skipped, because a clean retry would hide the rejection.
      </p>
      <p className="mt-2 rounded-md bg-blue-50 p-3 text-sm text-blue-900">
        Starting the authorization code flow carries no proof: that redirect only sends{' '}
        <span className="font-mono">dpop_jkt</span>. The first proof is built when the returned code
        is exchanged for a token, so that is where the fault takes effect. Client credentials and
        resource calls do send a proof straight away.
      </p>

      {armedFault && (
        <div className="mt-4 flex items-start justify-between gap-4 rounded-md border border-amber-300 bg-amber-50 p-4">
          <div>
            <p className="text-sm font-semibold text-amber-900">
              Armed: {armedFault.label}
            </p>
            <p className="mt-1 text-sm text-amber-800">
              Expecting HTTP 400 at the token endpoint or 401 at a resource call, with error{' '}
              <span className="font-mono">{armedFault.expectedError}</span>. Stays armed until you
              disarm it.
            </p>
          </div>
          <button
            onClick={() => dpop.armFault(null)}
            className="shrink-0 rounded-md bg-amber-600 px-3 py-2 text-sm text-white hover:bg-amber-700"
          >
            Disarm
          </button>
        </div>
      )}

      <div className="mt-6 rounded-md border border-gray-200 p-4">
        <div className="flex items-center justify-between gap-4">
          <div>
            <h3 className="text-sm font-semibold text-gray-900">Run all scenarios</h3>
            <p className="mt-0.5 text-sm text-gray-600">
              Sends every resource-call scenario in turn and checks the status and error code. Starts
              with a clean request, because if that one fails the rest proves nothing. Requires an
              access token.
            </p>
          </div>
          <button
            onClick={runSuite}
            disabled={running}
            className="shrink-0 rounded-md bg-blue-600 px-3 py-2 text-sm text-white hover:bg-blue-700 disabled:bg-gray-300"
          >
            {running ? 'Running...' : 'Run suite'}
          </button>
        </div>

        {baselineError && (
          <p className="mt-3 rounded-md bg-red-50 p-3 text-sm text-red-800">{baselineError}</p>
        )}

        {rows && rows.length > 0 && (
          <>
            <p className="mt-3 text-sm font-medium text-gray-800">
              {rows.filter((r) => r.passed).length} of {rows.length} behaved as expected
            </p>
            <div className="mt-2 overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="text-xs uppercase tracking-wide text-gray-500">
                    <th className="py-1 pr-3">Scenario</th>
                    <th className="py-1 pr-3">Status</th>
                    <th className="py-1 pr-3">Error</th>
                    <th className="py-1">Description (not judged)</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => (
                    <tr key={row.fault.key} className="border-t border-gray-100 align-top">
                      <td className="py-1 pr-3">
                        <span className={row.passed ? 'text-green-700' : 'text-red-700'}>
                          {row.passed ? 'ok' : 'unexpected'}
                        </span>{' '}
                        {row.fault.label}
                      </td>
                      <td className="py-1 pr-3 font-mono">{row.status}</td>
                      <td className="py-1 pr-3 font-mono">{row.error ?? '-'}</td>
                      <td className="py-1 text-gray-600">{row.description ?? '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="mt-2 text-xs text-gray-500">
              Nonce scenarios only reject while the server runs with DPoP nonces enabled; with nonces
              off they are accepted, which is correct rather than a regression.
            </p>
          </>
        )}
      </div>

      {faultGroups().map((group) => (
        <div key={group} className="mt-6">
          <h3 className="text-sm font-semibold uppercase tracking-wide text-gray-500">{group}</h3>
          <div className="mt-2 space-y-2">
            {DPOP_FAULTS.filter((fault) => fault.group === group).map((fault) => (
              <FaultRow
                key={fault.key}
                fault={fault}
                isArmed={armed === fault.key}
                onArm={() => dpop.armFault(armed === fault.key ? null : fault.key)}
              />
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

function FaultRow({
  fault,
  isArmed,
  onArm,
}: {
  fault: DpopFault
  isArmed: boolean
  onArm: () => void
}) {
  const resourceOnly = !fault.targets.includes('as')

  return (
    <div
      className={`flex items-start justify-between gap-4 rounded-md border p-3 ${
        isArmed ? 'border-amber-400 bg-amber-50' : 'border-gray-200 bg-white'
      }`}
    >
      <div className="min-w-0">
        <p className="text-sm font-medium text-gray-900">{fault.label}</p>
        <p className="mt-0.5 text-sm text-gray-600">{fault.description}</p>

        <div className="mt-1 flex flex-wrap gap-2">
          <Badge tone="gray">expects {fault.expectedError}</Badge>
          {resourceOnly && <Badge tone="blue">resource calls only</Badge>}
          {fault.requiresNonceMode && <Badge tone="blue">needs nonces enabled</Badge>}
          {fault.unreliableOn && <Badge tone="amber">unreliable at the token endpoint</Badge>}
        </div>

        {fault.unreliableOn && (
          <p className="mt-1 text-xs text-amber-800">{fault.unreliableOn.reason}</p>
        )}
      </div>

      <button
        onClick={onArm}
        className={`shrink-0 rounded-md px-3 py-2 text-sm ${
          isArmed
            ? 'bg-amber-600 text-white hover:bg-amber-700'
            : 'bg-gray-100 text-gray-800 hover:bg-gray-200'
        }`}
      >
        {isArmed ? 'Disarm' : 'Arm'}
      </button>
    </div>
  )
}

function Badge({ tone, children }: { tone: 'gray' | 'blue' | 'amber'; children: React.ReactNode }) {
  const tones = {
    gray: 'bg-gray-100 text-gray-700',
    blue: 'bg-blue-100 text-blue-800',
    amber: 'bg-amber-100 text-amber-900',
  }
  return (
    <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${tones[tone]}`}>{children}</span>
  )
}

/**
 * Reads one auth-param out of a WWW-Authenticate challenge. The name is matched up to the "=", so
 * looking for `error` does not also hit `error_description`.
 */
function challengeParam(challenge: string, name: string): string | undefined {
  return new RegExp(`(?:^|[\\s,])${name}="([^"]*)"`).exec(challenge)?.[1]
}
