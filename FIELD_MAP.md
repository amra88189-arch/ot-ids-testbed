# Host stream — full column map (TON_IoT ↔ CATF-IDS ↔ GRFICS lab)

The CATF-IDS host (Linux) model reads 10 features. TON_IoT's Linux subset was
collected with **atop**, which is also what we run in the lab — so the mapping is
the same tool on both sides, matched record by record, not an approximation.

`atop -P` emits one line per record type per process, after a common prefix:
`LABEL host epoch date time interval PID (command) state`. The indices below are
into the fields **after** `state` (0-based), as the converter reads them.

## The 10 host features

| # | CATF-IDS feature (`LOG_FEATURES`) | names the code accepts (`find_col`) | TON_IoT Linux column | atop record | atop field → our source | status |
|---|---|---|---|---|---|---|
| 1 | `cpu_usage`        | CPU, %CPU, cpu_usage, cpu, usr | **CPU**    | PRC | computed `100·(utime+stime)/(hertz·interval)`; hertz=PRC[0] utime=PRC[1] stime=PRC[2] | **confirmed** |
| 2 | `cpu_spike`        | — (derived)                    | —          | —   | derived: cpu − rolling median | derived |
| 3 | `disk_write`       | WRDSK, WR_SEC, DISK_WRITE, writes, blk_wrtn | **WRDSK** | PRD | WRDSK (KB written) = PRD field 4 | **confirmed** |
| 4 | `disk_write_delta` | — (derived)                    | —          | —   | derived: |Δ disk_write| | derived |
| 5 | `mem_usage`        | MEM, %MEM, VSZ, RSS, VSIZE, RSIZE | **MEM**  | PRM | RSIZE=PRM[2] (KB) | **confirmed** (scale note below) |
| 6 | `mem_vgrow`        | VGROW, vgrow, vmgrow           | **VGROW**  | PRM | VGROW=PRM[4] | **confirmed** |
| 7 | `mem_rgrow`        | RGROW, rgrow, rmgrow           | **RGROW**  | PRM | RGROW=PRM[5] | **confirmed** |
| 8 | `page_faults_min`  | MINFLT, minflt, minor_faults   | **MINFLT** | PRM | MINFLT=PRM[6] | **confirmed** |
| 9 | `page_faults_maj`  | MAJFLT, majflt, major_faults   | **MAJFLT** | PRM | MAJFLT=PRM[7] | **confirmed** |
| 10| `threads_run`      | TRUN, trun, threads_run        | **TRUN**   | PRG | TRUN = 2 tokens after the cmdline close-paren | **confirmed** |

## atop record layout on this build (atop 2.12.1), fields after `state`

**PRC (cpu) — confirmed**
```
[0] hertz(100)  [1] utime  [2] stime  [3] nice  [4] prio  [5] rtprio
[6] policy  [7] curcpu  [8] sleepavg(=0, obsolete)  [9] TGID  [10] isproc(y/n) ...
```
`y`/`n` at [10] = main process vs a subsidiary thread (the three java rows share
TGID 8061: `java`=y, `javamelody`/`Java2D Disposer`=n). Thread *counts* are NOT
in PRC — they live in PRG.

**PRM (memory) — confirmed against the live sample**
```
[0] pagesz  [1] VSIZE  [2] RSIZE  [3] shtext  [4] VGROW  [5] RGROW
[6] MINFLT  [7] MAJFLT ...
```

**PRG (general) — confirmed via a live busy/idle probe (`yes` vs `sleep`)**
```
... (cmdline — may contain spaces) PPID TRUN TSLPI TSLPU ...
```
TRUN is the 2nd token after the command-line close-paren. Verified: a Running
process reads 1 there, a Sleeping one 0 (with TSLPI = 1). Because the command
line contains spaces, the converter anchors on its parens instead of a fixed
index.

**PRD (disk) — confirmed on 10 s samples**
```
[0] flag  [1] flag  [2] RDDSK  [3] RDDSK  [4] WRDSK  [5] WRDSK  [6] WCANCL  [7] PID ...
```
WRDSK (KB written this interval) = field 4. Reads are field 2; both appear
duplicated (per-interval and cumulative, equal on the first since-boot sample).

## Processes vs threads

atop writes one line per process (flag `y`, totals over all its threads) and one
line per extra thread (flag `n`). Thread lines repeat the process's memory, so a
JVM with 81 threads summed to ~43 GB on a 7 GB VM. The converter keeps process
lines only. Flag position: PRC field 10, PRM field 13, PRD field 9, PRG five tokens
before the cgroup paren. Command names can contain spaces and parentheses
(`rs:main Q:Reg`, `(sd-pam)`), so lines are split on the single-letter state after
the name. A container with no hostname set (the HMI) is reported by its short
id; the converter maps ids to names with `docker ps`.

## Differences to keep in mind

1. **atop version.** TON_IoT used an older atop than 2.12.1, so a field's *position*
   can shift between versions. That is exactly why we pin every index empirically
   on this build (the `--verify-atop` dumps) instead of trusting a fixed layout.
   The feature *names* are unchanged across versions.
2. **MEM scale.** TON_IoT's `MEM` may be a memory-occupation percentage; we emit
   `RSIZE` in KB. This does not matter for the **site-retrain** evaluation (the host
   model is refit on lab data, and each model standard-scales its inputs). It *does*
   matter for the **transfer** evaluation (TON_IoT-trained model on lab host data):
   there we rescale `RSIZE` to the same units, or report the transfer host result
   with that caveat.
3. **Per-process vs aggregate.** TON_IoT's Linux records are per-process atop rows;
   our converter emits per-process rows too, so the granularity matches.
4. **Entity.** Our atop runs on the VM that hosts the containers. The realistic ICS
   "host" is the engineering workstation (EWS); running atop inside it later gives a
   more representative host stream (see lab/README.md).

## Status

All 10 host features confirmed against live samples on this build (atop 2.12.1):
- cpu_usage — PRC (hertz/utime/stime)
- mem_usage, mem_vgrow, mem_rgrow, page_faults_min, page_faults_maj — PRM
- disk_write — PRD field 4
- threads_run — PRG, anchored on the command-line parens
- cpu_spike, disk_write_delta — derived in the pipeline
