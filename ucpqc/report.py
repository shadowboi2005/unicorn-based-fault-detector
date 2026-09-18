"""Unified reporting for assessment results -- one console table and one bar
chart, subsuming the per-example printing/plotting.  matplotlib is a guarded
import so the console table always works even without it.
"""

# status -> (console tag, bar colour)
_STATUS = {
    "LEAK": ("LEAK", "#c44e52"),
    "ok": ("ok", "#55a868"),
    "crash": ("crash/hang", "#bdbdbd"),
    "control": ("control", "#4c72b0"),
}


def _fmt_metric(result, metric):
    if metric is None:
        return "  -- "
    if result.detector == "two_key":
        return f"{metric:4.0%}"
    if result.detector == "uniformity":
        return f"{metric:4.0%}"          # bin-share spike
    return f"{metric:.3g}"


def _fmt_p(p):
    """Format a per-site p-value (None in legacy mode, 0 for a certain violation)."""
    if p is None:
        return "  -- "
    if p <= 0:
        return "0"
    if p < 1e-4:
        return f"{p:.1e}"
    return f"{p:.4f}"


def format_table(result):
    """Return the console table for an `AssessmentResult` as a string."""
    calibrated = getattr(result, "calibrate", True)
    basis = (f"FDR q={result.fdr_q:g} ({result.correction}), n_perm={result.n_perm}"
             if calibrated else "legacy fixed thresholds")
    lines = []
    lines.append(f"{result.scheme}  mode={result.mode}  detector={result.detector}"
                 f"  N={result.n}/key  [{basis}]")
    head = f"  {'addr':>8}  {'site':<34} {'metric':>7} {'p':>9}  {'ran':>3} {'crash':>5}  status"
    lines.append(head)
    lines.append("  " + "-" * (len(head) - 2))
    for r in result.rows:
        tag, _ = _STATUS.get(r.status, (r.status, ""))
        addr = "" if r.addr is None else f"{r.addr:#06x}"
        flag = "  <- LEAK" if r.status == "LEAK" else ""
        lines.append(f"  {addr:>8}  {r.label:<34} {_fmt_metric(result, r.metric):>7} "
                     f"{_fmt_p(getattr(r, 'pvalue', None)):>9} {r.ran:>3} {r.crashed:>5}  "
                     f"{tag}{flag}")
    leaks = result.leaks()
    basis_note = f" at FDR<={result.fdr_q:g}" if calibrated else ""
    lines.append(f"  -> {len(leaks)} leaking site(s){basis_note}"
                 + (": " + ", ".join(f"{r.addr:#06x} {r.label}" for r in leaks)
                    if leaks else ""))
    return "\n".join(lines)


def plot_sweep(result, path):
    """Render the horizontal metric bar chart to `path` (PNG).  No-op with a
    warning if matplotlib is unavailable.  Returns the path or None."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("  (matplotlib not installed; skipping plot -- table only)")
        return None

    rows = result.rows
    names, vals, colors = [], [], []
    for r in rows:
        names.append(f"{'' if r.addr is None else f'{r.addr:#06x}'}  {r.label}")
        pct = (r.metric * 100) if (isinstance(r.metric, float) and r.status != "crash") else 0.0
        vals.append(pct)
        colors.append(_STATUS.get(r.status, ("", "#bdbdbd"))[1])

    fig, ax = plt.subplots(figsize=(9, max(3, 0.42 * len(rows) + 1)))
    y = np.arange(len(names))[::-1]
    ax.barh(y, vals, color=colors, edgecolor="white")
    if result.detector in ("two_key", "uniformity"):
        if not getattr(result, "calibrate", True):     # legacy: show the fixed cutoff
            ax.axvline(80, color="#c44e52", ls="--", lw=1, label="leak threshold (80%)")
        ax.axvline(50, color="#888888", ls=":", lw=1, label="chance (50%)")
        ax.set_xlim(0, 100)
        ax.set_xlabel(f"{result.detector} metric (%)")
    for yi, r, v in zip(y, rows, vals):
        txt = "crash/hang" if r.status == "crash" else _fmt_metric(result, r.metric).strip()
        ax.text(1.5, yi, txt, va="center", ha="left", fontsize=7.5,
                color="white" if v > 12 else "black")
    ax.set_yticks(y); ax.set_yticklabels(names, fontsize=7, family="monospace")
    ax.set_title(f"{result.scheme}  {result.mode} sweep ({result.detector}, N={result.n}/key)")
    ax.legend(loc="lower right", fontsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)
    return path
