import { ATTEMPT_CODE, ATTEMPT_KIND, CAPABILITY_STATE, deepFreeze } from '../contracts.mjs';
import { validContainedBrowserLaunchPlan } from '../process.mjs';

const CONTAINED_LAUNCH = Object.freeze({ shell: false });

function outcome(kind, code, details) {
  return deepFreeze({ kind, code, ...(details ? { details } : {}) });
}

export function createPlaywrightAdapter({ capability, sandbox, supervisor } = {}) {
  const current = deepFreeze({ ...(capability ?? {
    state: CAPABILITY_STATE.UNAVAILABLE_SECURITY_GATE,
    reason: 'proof_missing',
  }) });

  return Object.freeze({
    id: 'playwright',
    version: current.version ?? null,
    async probe() { return current; },
    async run({ job, request } = {}) {
      if (current.state !== CAPABILITY_STATE.READY) {
        return outcome(ATTEMPT_KIND.SKIP, ATTEMPT_CODE.POLICY_UNENFORCEABLE, {
          reason: current.reason ?? 'proof_missing',
        });
      }
      if (!sandbox?.proofEligible || typeof sandbox.launch !== 'function') {
        return outcome(ATTEMPT_KIND.SKIP, ATTEMPT_CODE.POLICY_UNENFORCEABLE, {
          reason: sandbox?.reason ?? 'sandbox_unavailable',
        });
      }
      if (!supervisor || typeof supervisor.run !== 'function') {
        return outcome(ATTEMPT_KIND.BROKEN, ATTEMPT_CODE.ADAPTER_PROTOCOL_ERROR, {
          reason: 'browser_supervisor_unavailable',
        });
      }
      if (!job || job.policy?.allowRendered !== true || typeof job.target?.url !== 'string') {
        return outcome(ATTEMPT_KIND.SKIP, ATTEMPT_CODE.POLICY_UNENFORCEABLE, {
          reason: 'rendered_not_allowed',
        });
      }
      let launchPlan;
      try {
        launchPlan = sandbox.launch();
      } catch {}
      if (!validContainedBrowserLaunchPlan(launchPlan)
          || launchPlan.shell !== CONTAINED_LAUNCH.shell) {
        return outcome(ATTEMPT_KIND.SKIP, ATTEMPT_CODE.POLICY_UNENFORCEABLE, {
          reason: 'containment_launch_plan_invalid',
        });
      }
      const result = await supervisor.run('python-browser', {
        launchPlan,
        request: {
          version: 1,
          id: request?.id ?? 'render',
          operation: 'render',
          url: job.target.url,
          output_path: request?.outputPath,
          wait_ms: request?.waitMs ?? 0,
          scroll_steps: request?.scrollSteps ?? 0,
          scroll_y: request?.scrollY ?? 0,
          proxy: request?.proxy,
        },
        signal: request?.signal,
      });
      if (result?.kind !== ATTEMPT_KIND.SUCCESS) {
        return result ?? outcome(ATTEMPT_KIND.BROKEN, ATTEMPT_CODE.ADAPTER_PROTOCOL_ERROR, {
          reason: 'browser_protocol_failed',
        });
      }
      if (result.response?.ok !== true) {
        return result.response?.code === 'render_failed'
          ? outcome(ATTEMPT_KIND.RETRYABLE, ATTEMPT_CODE.NETWORK, { reason: 'render_failed' })
          : outcome(ATTEMPT_KIND.BROKEN, ATTEMPT_CODE.ADAPTER_PROTOCOL_ERROR, {
            reason: 'browser_protocol_failed',
          });
      }
      return outcome(ATTEMPT_KIND.SUCCESS, ATTEMPT_CODE.OK, {
        ...result.response.payload,
        proofFingerprint: current.proofFingerprint,
      });
    },
  });
}
