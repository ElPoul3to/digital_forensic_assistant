"""``dfa`` command line interface."""

from __future__ import annotations

import logging

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Digital Forensic Assistant: retrieve & rerank RAG for incident response.", no_args_is_help=True)
case_app = typer.Typer(help="Manage investigation cases.")
external_app = typer.Typer(help="Manage external knowledge (MITRE ATT&CK).")
user_app = typer.Typer(help="Manage API users and tokens.")
bundle_app = typer.Typer(help="Air-gapped install bundle.")
store_app = typer.Typer(help="Vector store (Qdrant): status, embedded -> server migration.")
app.add_typer(case_app, name="case")
app.add_typer(store_app, name="store")
app.add_typer(external_app, name="external")
app.add_typer(user_app, name="user")
app.add_typer(bundle_app, name="bundle")
console = Console()


class _LogFormat(logging.Formatter):
    """Progress lines as-is; warnings and errors prefixed with their level and logger."""

    def format(self, record: logging.LogRecord) -> str:
        msg = record.getMessage()
        if record.levelno >= logging.WARNING:
            return f"[{record.levelname.lower()}] {record.name}: {msg}"
        if record.name != "dfa.progress":
            return f"{record.name.rsplit('.', 1)[-1]}: {msg}"
        return msg


@app.callback()
def _root(verbose: bool = typer.Option(False, "--verbose", "-v", help="Debug logging (also lists every skipped file during ingest)")) -> None:
    from rich.logging import RichHandler

    handler = RichHandler(console=Console(stderr=True), show_path=False, show_level=False, markup=False,
                          rich_tracebacks=False, log_time_format="%H:%M:%S")
    handler.setFormatter(_LogFormat())
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, handlers=[handler], force=True)
    for noisy in ("httpx", "httpcore", "sentence_transformers", "transformers", "urllib3", "qdrant_client", "huggingface_hub", "torch", "filelock"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


@app.command()
def smoke() -> None:
    """End-to-end check: embed, store, hybrid-search, and ping the LLM."""
    from dfa.ingestion.schema import Chunk, Granularity
    from dfa.retrieval.embedder import get_embedder
    from dfa.retrieval.store import get_store

    emb = get_embedder()
    console.print(f"[green]embedder[/] {emb.name} dim={emb.dim}")
    store = get_store()
    coll = "case__smoke"
    store.drop_collection(coll)

    docs = [
        "Mar 16 08:12:09 app-1 sudo: user3 : TTY=tty1 ; PWD=/home/user3 ; USER=root ; COMMAND=/bin/su",
        "Apr 20 04:31:11 app-1 sshd[9021]: Accepted password for root from 190.166.87.164 port 41113 ssh2",
        "Apr 19 12:00:30 app-1 dpkg: install python-tz <none> 2007k-0ubuntu2",
        "10.0.1.2 - - [19/Apr/2010:06:36:15 -0700] \"GET /feed/ HTTP/1.1\" 200 16605",
    ]
    chunks = [
        Chunk(chunk_id=Chunk.make_id(coll, str(i)), collection=coll, text=d, granularity=Granularity.EVENT, metadata={"i": i})
        for i, d in enumerate(docs)
    ]
    n = store.upsert(chunks, emb.embed_documents(docs))
    console.print(f"[green]stored[/] {n} chunks in {coll}")

    q = "successful ssh root login from 190.166.87.164"
    hits = store.hybrid_search(coll, q, emb.embed_queries([q])[0], dense_k=10, sparse_k=10, rrf_k=60, limit=3)
    t = Table(title=f"hybrid search: {q}")
    t.add_column("score")
    t.add_column("text")
    for h in hits:
        t.add_row(f"{h.score:.4f}", h.payload["text"][:90])
    console.print(t)
    ok = bool(hits) and "190.166.87.164" in hits[0].payload["text"]
    console.print("[green]retrieval OK[/]" if ok else "[red]retrieval returned an unexpected top hit[/]")
    store.drop_collection(coll)

    from dfa.generation.llm import get_llm

    llm = get_llm()
    reply = llm.complete("Reply with the single word READY.", max_tokens=8)
    console.print(f"[green]llm[/] {llm.model} -> {reply.strip()!r}")


@app.command()
def detect(paths: list[str] = typer.Argument(..., help="Files or directories to sniff")) -> None:
    """Identify file formats by magic bytes / content (no parsing)."""
    from pathlib import Path

    from dfa.ingestion.agent import IngestionAgent
    from dfa.ingestion.parsers.base import parser_for

    agent = IngestionAgent(case_id="_detect")
    t = Table("file", "kind", "conf", "description", "parser")
    for p, d in agent.detect_all([Path(x) for x in paths]):
        has = "yes" if parser_for(d.kind) else ("container" if d.container else "[red]no[/]")
        t.add_row(str(p), d.kind, f"{d.confidence:.2f}", d.description, has)
    console.print(t)


@app.command()
def ingest(
    paths: list[str] = typer.Argument(..., help="Files or directories of evidence"),
    case: str = typer.Option(..., "--case", "-c", help="Case id"),
    host: str | None = typer.Option(None, "--host", help="Host name to attach to events lacking one"),
    year: int | None = typer.Option(None, "--year", help="Year for timestamps that lack one (BSD syslog)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Parse only, do not embed or store"),
    no_triage: bool = typer.Option(
        False, "--no-triage",
        help="Parse every file. By default known-noise files of full disk / triage collections are skipped "
             "(fonts, UI bundles, caches, code, large timestamp-less text such as word lists)",
    ),
    all_files: bool = typer.Option(False, "--all-files", help="List every file in the report, including skipped and unsupported ones"),
) -> None:
    """Sniff, parse, embed and index evidence files into a case."""
    import time
    from collections import Counter
    from pathlib import Path

    from dfa.ingestion.agent import IngestionAgent
    from dfa.ingestion.pipeline import index_events

    t0 = time.time()
    agent = IngestionAgent(case_id=case, host_hint=host, year_hint=year, triage=not no_triage)
    events = agent.events([Path(p) for p in paths])
    if dry_run:
        n = sum(1 for _ in events)
        console.print(f"[yellow]dry run[/] parsed {n} events in {time.time() - t0:.0f}s")
    else:
        stats = index_events(case, events)
        console.print(f"[green]indexed[/] {stats['events']} events -> {stats['chunks']} chunks in case {case} ({time.time() - t0:.0f}s)")

    files = agent.report.files
    shown = files if all_files else [f for f in files if f.status == "error" or (f.status == "parsed" and f.events)]
    t = Table("file", "kind", "status", "events", "note")
    for f in shown:
        colour = {"parsed": "green", "unsupported": "yellow", "error": "red", "skipped": "yellow"}.get(f.status, "")
        t.add_row(f.path, f.detection.kind, f"[{colour}]{f.status}[/]", str(f.events), f.error or "")
    console.print(t)

    by_status = Counter(f.status for f in files)
    console.print("files: " + ", ".join(f"{k} {n}" for k, n in sorted(by_status.items())) + f" (total {len(files)})")
    if not all_files:
        reasons = Counter((f.error or "").split(" (")[0].split(": ", 1)[-1][:60] for f in files if f.status == "skipped")
        if reasons:
            console.print("skipped: " + "; ".join(f"{r} ×{n}" for r, n in reasons.most_common(8)))
        unsupported = Counter(f.detection.kind for f in files if f.status == "unsupported")
        if unsupported:
            console.print("unsupported (no parser): " + ", ".join(f"{k} ×{n}" for k, n in unsupported.most_common(8)))
        console.print("[dim]--all-files lists every file; --no-triage parses the skipped ones too[/]")


@app.command()
def ask(
    question: str = typer.Argument(..., help="Analyst question"),
    case: str = typer.Option(..., "--case", "-c"),
    route: str = typer.Option("auto", "--route", help="auto | evidence_only | evidence+attack | attack_only"),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable output"),
    no_rewrite: bool = typer.Option(False, "--no-rewrite", help="Skip LLM query rewriting (faster)"),
    navigator: str | None = typer.Option(None, "--navigator", help="Write an ATT&CK Navigator layer (JSON) of the cited techniques"),
) -> None:
    """Ask one question over a case and print the grounded answer with citations."""
    import json as _json
    from pathlib import Path

    from dfa.generation.answer import ask as _ask

    if json_out:
        a = _ask(case, question, route=route, use_rewriter=not no_rewrite)
        print(_json.dumps(a.to_dict(), indent=2, default=str))
    else:
        a = _ask(case, question, route=route, use_rewriter=not no_rewrite, stream_cb=lambda t: console.print(t, end="", markup=False))
        console.print()
        _print_sources(a)
    if navigator:
        Path(navigator).write_text(_json.dumps(a.navigator_layer(case), indent=2))
        console.print(f"[green]navigator layer[/] {navigator} ({len(a.attack_techniques)} techniques)")


def _print_sources(a) -> None:
    console.print(f"\n[dim]route={a.route} ({a.route_reason})  filters={a.filters}  queries={len(a.queries)}[/]")
    for h in a.hops:
        console.print(f"[dim]hop: {h['query']}  (+{h['added']} evidence) {h['why']}[/]", markup=False)
    if a.invalid_citations:
        console.print(f"[red]unverified citations:[/] {', '.join(a.invalid_citations)}")
    if a.timeline_query:
        tq = a.timeline_query
        if tq.get("error"):
            console.print(f"[yellow]timeline query failed:[/] {tq['error']}")
        else:
            console.print(f"[dim]timeline query ({tq['total']} rows):[/] {tq['sql']}", markup=False)
    t = Table("label", "source", "where", "time", "rerank")
    for c in a.citations:
        if c["kind"] == "timeline":
            t.add_row(c["label"], "timeline query", (c.get("note") or "")[:60], f"{c['rows']} rows", "")
        elif c["kind"] == "evidence":
            t.add_row(c["label"], c["source_file"] or "", c["record_ref"] or "", c["ts"] or "", f"{c['rerank']:.2f}" if c["rerank"] is not None else "")
        else:
            t.add_row(c["label"], c["kind"], (c.get("name") or "")[:60], "", f"{c['rerank']:.2f}" if c["rerank"] is not None else "")
    console.print(t)


@app.command()
def chat(
    case: str = typer.Option(..., "--case", "-c"),
    route: str = typer.Option("auto", "--route"),
    no_rewrite: bool = typer.Option(False, "--no-rewrite"),
) -> None:
    """Interactive chat over a case. Commands: /route <label>, /sources, /navigator <file.json>, /clear, /exit."""
    from pathlib import Path

    from dfa.generation.answer import ask as _ask
    from dfa.generation.navigator import LayerBuilder

    history: list[dict] = []
    last = None
    layer = LayerBuilder(case)
    console.print(f"[bold]Digital Forensic Assistant[/] case={case} route={route}. Type /exit to quit.")
    while True:
        try:
            q = console.input("[bold cyan]> [/]").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not q:
            continue
        if q in ("/exit", "/quit"):
            break
        if q == "/clear":
            history.clear(); console.print("[dim]history cleared[/]"); continue
        if q == "/sources":
            if last: _print_sources(last)
            continue
        if q.startswith("/route"):
            route = q.split(maxsplit=1)[1] if " " in q else "auto"; console.print(f"[dim]route={route}[/]"); continue
        if q.startswith("/navigator"):
            out = Path(q.split(maxsplit=1)[1] if " " in q else f"{case}-navigator.json")
            layer.write(out); console.print(f"[green]navigator layer[/] {out} ({len(layer.techniques)} techniques from this session)"); continue
        try:
            last = _ask(case, q, route=route, history=history, use_rewriter=not no_rewrite,
                        stream_cb=lambda t: console.print(t, end="", markup=False))
        except Exception as e:  # noqa: BLE001
            console.print(f"[red]error:[/] {e}"); continue
        console.print()
        _print_sources(last)
        layer.add(last)
        history += [{"role": "user", "content": q}, {"role": "assistant", "content": last.answer}]


@app.command()
def timeline(
    case: str = typer.Argument(..., help="Case id"),
    ts_from: str | None = typer.Option(None, "--from", help="Start (ISO date/time, UTC)"),
    ts_to: str | None = typer.Option(None, "--to", help="End (ISO date/time, UTC)"),
    host: str | None = typer.Option(None, "--host"),
    user: str | None = typer.Option(None, "--user"),
    ip: str | None = typer.Option(None, "--ip"),
    category: str | None = typer.Option(None, "--category", "-k", help="authentication | privilege | web | ..."),
    action: str | None = typer.Option(None, "--action", "-a", help="e.g. ssh_login_success (see --values action)"),
    source_file: str | None = typer.Option(None, "--file", "-f", help="Only events from this source file"),
    grep: str | None = typer.Option(None, "--grep", "-g", help="Substring in summary or raw line (case-insensitive)"),
    around: str | None = typer.Option(None, "--around", help="ISO time or event id: show -n/+n events around it"),
    n: int = typer.Option(10, "-n", help="Events on each side for --around"),
    limit: int = typer.Option(100, "--limit", "-l", help="Rows to print (or export with --html)"),
    offset: int = typer.Option(0, "--offset", help="Skip this many rows (paging)"),
    histogram: str | None = typer.Option(None, "--histogram", help="minute | hour | day | week | month: events per bucket by category"),
    values: str | None = typer.Option(None, "--values", help="host | user | category | action | source_file: distinct values with counts"),
    ids: bool = typer.Option(False, "--ids", help="Also print event ids (for --around)"),
    html: str | None = typer.Option(None, "--html", help="Write a self-contained HTML timeline (histogram + filters + table) to this file"),
    raw_chars: int = typer.Option(400, "--raw-chars", help="Raw line length kept in the HTML export"),
) -> None:
    """Browse the case timeline: filter, page, look around an event, histogram, or export to HTML."""
    from dfa.ingestion import timeutil
    from dfa.timeline.store import get_timeline

    tl = get_timeline(case)
    f_from = timeutil.parse_any(ts_from) if ts_from else None
    f_to = timeutil.parse_any(ts_to) if ts_to else None
    if (ts_from and not f_from) or (ts_to and not f_to):
        raise typer.BadParameter("could not parse --from / --to")
    filters = {"host": host, "user": user, "ip": ip, "category": category, "action": action, "source_file": source_file,
               "ts_from": f_from, "ts_to": f_to, "text": grep}

    if values:
        t = Table(values, "events")
        for v, c in tl.distinct(values):
            t.add_row(str(v), str(c))
        console.print(t)
        return

    if histogram:
        rows = tl.histogram(histogram, **filters)
        if not rows:
            console.print("[yellow]no timestamped events match[/]"); return
        buckets: dict = {}
        for r in rows:
            b = buckets.setdefault(r["bucket"], {})
            b[r["category"]] = r["n"]
        top = max(sum(b.values()) for b in buckets.values())
        fmt = "%Y-%m-%d %H:%M" if histogram in ("minute", "hour") else "%Y-%m-%d"
        t = Table(histogram, "events", "", "by category")
        for when, b in buckets.items():
            tot = sum(b.values())
            bar = "█" * max(1, round(40 * tot / top))
            t.add_row(when.strftime(fmt), str(tot), f"[cyan]{bar}[/]", "  ".join(f"{k} {v}" for k, v in sorted(b.items(), key=lambda kv: -kv[1])[:4]))
        console.print(t)
        console.print(f"[dim]{len(buckets)} buckets, {sum(sum(b.values()) for b in buckets.values())} events; narrow with --from/--to or filters[/]")
        return

    if around:
        when = timeutil.parse_any(around)
        if when is None:
            hit = tl.get([around])
            if not hit or hit[0]["ts"] is None:
                raise typer.BadParameter(f"--around: not a time and no event with id {around!r}")
            when = hit[0]["ts"]
        rows = tl.around(when, n=n, **filters)
        total = len(rows)
    else:
        total = tl.count(**filters)
        rows = tl.search(limit=limit, offset=offset, **filters)

    if html:
        from pathlib import Path

        from dfa.timeline import export

        if not around and total > limit:
            console.print(f"[yellow]{total} events match; exporting the first {limit} (raise --limit or add filters)[/]")
        out = export.write(Path(html), case, rows, total=total, filters=filters, raw_chars=raw_chars)
        console.print(f"[green]wrote[/] {out} ({out.stat().st_size / 1e6:.1f} MB, {len(rows)} events). Open it in a browser.")
        return

    t = Table(show_lines=False, pad_edge=False)
    t.add_column("time (UTC)", no_wrap=True)
    t.add_column("host", no_wrap=True, max_width=14)
    t.add_column("user", no_wrap=True, max_width=14)
    t.add_column("category / action", max_width=26)
    t.add_column("summary", ratio=3, overflow="fold")
    t.add_column("source", max_width=22)
    if ids:
        t.add_column("event id", no_wrap=True)
    for r in rows:
        ts = r["ts"].strftime("%Y-%m-%d %H:%M:%S") if r.get("ts") else "-"
        cells = [ts, r.get("host") or "", r.get("user") or "", f"{r.get('category') or ''} {r.get('action') or ''}".strip(),
                 (r.get("summary") or "")[:160], f"{r.get('source_file') or ''} {r.get('record_ref') or ''}"]
        if ids:
            cells.append(r["event_id"])
        t.add_row(*cells)
    console.print(t)
    if around:
        console.print(f"[dim]{len(rows)} events around {when:%Y-%m-%dT%H:%M:%SZ}[/]")
    else:
        console.print(f"[dim]rows {offset + 1}-{offset + len(rows)} of {total}; --offset {offset + limit} for the next page, --html out.html to export[/]")


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Start the REST API (POST /chat, POST /ingest, GET /cases). Tokens: dfa user add."""
    import uvicorn

    from dfa.api.auth import load_users
    from dfa.config import get_settings

    mode = get_settings().security.api_auth
    if not load_users() and mode != "off":
        if host not in ("127.0.0.1", "localhost", "::1"):
            console.print("[red]no API users configured[/]: remote clients will be refused. Create one with `dfa user add <name> --role admin`.")
        else:
            console.print("[yellow]no API users configured[/]: local requests are accepted as an anonymous admin (security.api_auth=auto).")
    uvicorn.run("dfa.api.app:app", host=host, port=port, log_level="info")


def _case_assets(case_id: str) -> dict:
    """Everything on disk that belongs to a case: vector collection, timeline DB, raw artefact dir."""
    from dfa.config import get_settings
    from dfa.retrieval.store import case_collection

    s = get_settings()
    return {"collection": case_collection(case_id), "timeline": s.timeline_dir / f"{case_id}.duckdb", "files": s.cases_dir / case_id,
            "audit": s.data_dir / "audit" / f"{case_id}.jsonl"}


def _known_cases() -> list[str]:
    from dfa.config import get_settings
    from dfa.retrieval.store import get_store

    s = get_settings()
    ids = {c.removeprefix("case_") for c in get_store().list_collections() if c.startswith("case_")}
    ids |= {p.stem for p in s.timeline_dir.glob("*.duckdb")} if s.timeline_dir.exists() else set()
    ids |= {p.name for p in s.cases_dir.iterdir() if p.is_dir()} if s.cases_dir.exists() else set()
    return sorted(ids)


def _dir_size(p) -> int:
    return sum(f.stat().st_size for f in p.rglob("*") if f.is_file()) if p.exists() else 0


@case_app.command("list")
def case_list() -> None:
    """List every case: indexed chunks, timeline events, raw files and disk usage."""
    from dfa.retrieval.store import get_store
    from dfa.timeline.store import Timeline

    store = get_store()
    from dfa.security import crypto

    t = Table("case", "chunks", "events", "time range", "raw files", "disk", "encrypted")
    for cid in _known_cases():
        a = _case_assets(cid)
        events, span = "-", ""
        if a["timeline"].exists():
            try:
                tl = Timeline(cid)
                st = tl.stats()
                tl.close()
                events = str(st["events"])
                if st["time_min"]:
                    span = f"{st['time_min']:%Y-%m-%d} .. {st['time_max']:%Y-%m-%d}"
            except Exception as e:  # noqa: BLE001  (locked by a running dfa chat / serve)
                events = f"[yellow]locked[/] ({type(e).__name__})"
        nfiles = sum(1 for f in a["files"].rglob("*") if f.is_file()) if a["files"].exists() else 0
        size = _dir_size(a["files"]) + (a["timeline"].stat().st_size if a["timeline"].exists() else 0)
        t.add_row(cid, str(store.count(a["collection"])), events, span, str(nfiles), f"{size / 1e6:.0f} MB", "[green]yes[/]" if crypto.is_encrypted(cid) else "no")
    console.print(t)


@case_app.command("new")
def case_new(case_id: str, encrypt: bool = typer.Option(False, "--encrypt", help="Create a per-case key: timeline, indexed text and audit log are encrypted at rest")) -> None:
    """Create an empty case."""
    from dfa.config import get_settings
    from dfa.retrieval.store import case_collection, get_store
    from dfa.security import crypto

    get_settings().cases_dir.joinpath(case_id).mkdir(parents=True, exist_ok=True)
    if encrypt or get_settings().security.encrypt_new_cases:
        crypto.create_case_key(case_id)
    get_store().ensure_collection(case_collection(case_id))
    console.print(f"[green]created[/] case {case_id}" + (" [cyan](encrypted)[/]" if crypto.is_encrypted(case_id) else ""))


@case_app.command("encrypt")
def case_encrypt(case_id: str, yes: bool = typer.Option(False, "--yes", "-y")) -> None:
    """Turn encryption on for an existing case: re-encrypts the timeline, the indexed text and the audit log in place."""
    from dfa.security import crypto
    from dfa.security.migrate import encrypt_case

    if crypto.is_encrypted(case_id):
        console.print(f"case {case_id} is already encrypted")
        return
    if not yes and not typer.confirm(f"Encrypt case {case_id} in place? Quit any running dfa chat / serve first."):
        raise typer.Abort()
    res = encrypt_case(case_id)
    console.print(f"[green]encrypted[/] case {case_id}: timeline={res['timeline']} points={res['points']} audit_lines={res['audit']}; key {res['key']}")


@case_app.command("stats")
def case_stats(case_id: str) -> None:
    """Show what is indexed for a case: counts, time range, hosts, users, top IPs."""
    from dfa.timeline.store import get_timeline

    st = get_timeline(case_id).stats()
    console.print(f"[bold]case {case_id}[/]  events={st['events']}  time={st['time_min']} .. {st['time_max']}")
    console.print(f"hosts: {', '.join(st['hosts']) or '-'}")
    console.print(f"users: {', '.join(st['users']) or '-'}")
    t = Table("source file", "events")
    for k, v in st["by_source"].items():
        t.add_row(str(k), str(v))
    console.print(t)
    t = Table("category", "events")
    for k, v in st["by_category"].items():
        t.add_row(str(k), str(v))
    console.print(t)
    t = Table("ip", "events")
    for ip, n in st["top_ips"]:
        t.add_row(ip, str(n))
    console.print(t)


@case_app.command("audit")
def case_audit(case_id: str, limit: int = typer.Option(20, "--limit", "-l"), json_out: bool = typer.Option(False, "--json")) -> None:
    """Show the audit log of a case: who asked what, how it was routed, which records were shown."""
    import json as _json

    from dfa.generation.audit import audit_path, read

    entries = read(case_id, limit=limit)
    if json_out:
        print(_json.dumps(entries, indent=2))
        return
    if not entries:
        console.print(f"[yellow]no audit entries[/] ({audit_path(case_id)})")
        return
    t = Table("time (UTC)", "user", "via", "route", "question", "records shown", "cited", "SQL")
    for e in entries:
        tq = e.get("timeline_query") or {}
        t.add_row(e["ts"], e.get("user") or "", e.get("interface", ""), e["route"], e["question"][:70], str(len(e.get("retrieved", []))),
                  ",".join(e.get("cited", [])), (tq.get("sql") or "")[:60])
    console.print(t)
    console.print(f"[dim]{audit_path(case_id)}[/]")


@case_app.command("rm")
def case_rm(
    case_id: str,
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask for confirmation"),
    keep_files: bool = typer.Option(False, "--keep-files", help="Keep data/cases/<id>/ (raw artefacts copied into the project)"),
) -> None:
    """Delete everything belonging to a case: vector collection, timeline DB and data/cases/<id>/."""
    import shutil

    from dfa.retrieval.store import get_store

    a = _case_assets(case_id)
    store = get_store()
    present = []
    if store.client.collection_exists(a["collection"]):
        present.append(f"vector collection {a['collection']} ({store.count(a['collection'])} chunks)")
    if a["timeline"].exists():
        present.append(f"timeline {a['timeline']} ({a['timeline'].stat().st_size / 1e6:.0f} MB)")
    if a["files"].exists() and not keep_files:
        present.append(f"raw files {a['files']} ({_dir_size(a['files']) / 1e6:.0f} MB)")
    if a["audit"].exists():
        present.append(f"audit log {a['audit']}")
    if not present:
        console.print(f"[yellow]nothing found[/] for case {case_id}")
        return
    console.print("Will delete:\n  " + "\n  ".join(present))
    if not yes and not typer.confirm("Continue?"):
        raise typer.Abort()
    store.drop_collection(a["collection"])
    for p in (a["timeline"], a["timeline"].with_suffix(".duckdb.wal")):
        if p.exists():
            p.unlink()
    if a["files"].exists() and not keep_files:
        shutil.rmtree(a["files"])
    if a["audit"].exists():
        a["audit"].unlink()
    from dfa.security import crypto

    if crypto.is_encrypted(case_id):
        crypto.key_path(case_id).unlink()
        crypto.case_key.cache_clear()
    console.print(f"[yellow]deleted[/] case {case_id}")


@external_app.command("update-attack")
def external_update_attack(
    domain: str = typer.Option("enterprise", help="enterprise | mobile | ics"),
    file: str | None = typer.Option(None, help="Use a local STIX bundle instead of downloading"),
) -> None:
    """Download (or load) the ATT&CK STIX bundle and (re)index it."""
    from pathlib import Path

    from dfa.ingestion.external.attack_stix import update

    res = update(domain, Path(file) if file else None)
    console.print(f"[green]ATT&CK {domain}[/] indexed {res['chunks']} chunks")


@external_app.command("status")
def external_status() -> None:
    """Chunk counts of the external collections."""
    from dfa.retrieval.store import EXTERNAL_COLLECTIONS, get_store

    store = get_store()
    t = Table("collection", "chunks")
    for c in EXTERNAL_COLLECTIONS:
        t.add_row(c, str(store.count(c)))
    console.print(t)


@app.command()
def disk(
    image: str = typer.Argument(..., help="Disk image (E01, raw, VMDK, VHDX, qcow2, ...) or evidence directory"),
    case: str = typer.Option(..., "--case", "-c"),
    plugins: str | None = typer.Option(None, "--plugins", "-p", help="Comma-separated dissect plugins (default: the OS list, see --list)"),
    host: str | None = typer.Option(None, "--host"),
    list_only: bool = typer.Option(False, "--list", help="Show the OS, hostname and available plugins, extract nothing"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Extract artefacts from a disk image or directory with dissect.target and index them into a case."""
    from pathlib import Path

    from dfa.agents.disk import DiskAgent
    from dfa.ingestion.parsers.base import ParseContext

    agent = DiskAgent(plugins=[p.strip() for p in plugins.split(",")] if plugins else None)
    if list_only:
        info = agent.describe(agent.open(Path(image)))
        console.print(info)
        t = Table("plugin", "description")
        for pl in agent.plugin_list(info.get("os")):
            t.add_row(pl.name, pl.description)
        console.print(t)
        return
    events = agent.parse(Path(image), ParseContext(case_id=case, host_hint=host))
    if dry_run:
        n = sum(1 for _ in events)
        console.print(f"[yellow]dry run[/] {n} events")
    else:
        from dfa.ingestion.pipeline import index_events

        stats = index_events(case, events)
        console.print(f"[green]indexed[/] {stats['events']} events -> {stats['chunks']} chunks in case {case}")
    console.print(agent.info)
    t = Table("plugin", "status", "records", "note")
    for r in agent.results:
        t.add_row(r.name, r.status, str(r.records), r.error or "")
    console.print(t)


@app.command()
def memory(
    image: str = typer.Argument(..., help="Memory image (raw, LiME, crash dump, hiberfil, vmem)"),
    case: str = typer.Option(..., "--case", "-c"),
    plugins: str | None = typer.Option(None, "--plugins", "-p", help="Comma-separated Volatility plugins (default: the OS list minus the slow ones)"),
    host: str | None = typer.Option(None, "--host"),
    timeout: int = typer.Option(1800, "--timeout", help="Seconds per plugin"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Run Volatility 3 plugins on a memory image and index the rows into a case."""
    from pathlib import Path

    from dfa.agents.memory import MemoryAgent
    from dfa.ingestion.parsers.base import ParseContext

    agent = MemoryAgent(plugins=[p.strip() for p in plugins.split(",")] if plugins else None, timeout=timeout)
    events = agent.parse(Path(image), ParseContext(case_id=case, host_hint=host))
    if dry_run:
        n = sum(1 for _ in events)
        console.print(f"[yellow]dry run[/] {n} events (os={agent.os_name})")
    else:
        from dfa.ingestion.pipeline import index_events

        stats = index_events(case, events)
        console.print(f"[green]indexed[/] {stats['events']} events -> {stats['chunks']} chunks in case {case} (os={agent.os_name})")
    t = Table("plugin", "status", "rows", "seconds", "note")
    for r in agent.runs:
        t.add_row(r.name, r.status, str(r.rows), str(r.seconds), r.error or "")
    console.print(t)


@app.command()
def investigate(
    question: str = typer.Argument(..., help="The question to answer"),
    paths: list[str] = typer.Argument(..., help="Disk images, memory images, evidence directories or files"),
    case: str = typer.Option(..., "--case", "-c"),
    rounds: int = typer.Option(2, "--rounds", help="Extraction rounds"),
    per_round: int = typer.Option(4, "--per-round", help="Extractors per round"),
    host: str | None = typer.Option(None, "--host"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Let the model choose which artefacts to extract for a question, extract them, answer, and refine once."""
    import json
    from pathlib import Path

    from dfa.agents.investigate import investigate as _investigate

    inv = _investigate(case, [Path(p) for p in paths], question, max_rounds=rounds, per_round=per_round, host=host,
                       progress=lambda m: console.print(f"[dim]{m}[/]"))
    if json_out:
        console.print_json(json.dumps(inv.to_dict(), default=str))
        return
    for i, r in enumerate(inv.rounds, 1):
        console.print(f"[bold]round {i}[/] ({r.seconds}s): " + ", ".join(f"{k} ({r.events.get(k, 0)} events{', ' + r.errors[k] if k in r.errors else ''})" for k in r.chosen))
    if inv.answer is not None:
        console.print("\n[bold]Answer[/]\n" + inv.answer.answer)
        _print_sources(inv.answer)
    else:
        console.print("[yellow]nothing extracted[/]: no supported artefact found")


@store_app.command("status")
def store_status() -> None:
    """Show the vector store mode (embedded / server) and the point count per collection."""
    from dfa.config import get_settings
    from dfa.retrieval.store import get_store

    cfg = get_settings().vector_store
    console.print(f"mode: [bold]{'server ' + cfg.url if cfg.url else 'embedded ' + str(cfg.path)}[/]")
    if not cfg.url:
        console.print("[yellow]embedded mode writes ~50 chunks/s and loads every collection into RAM on open; "
                      "use `make qdrant-server` + DFA_QDRANT_URL for real cases[/]")
    store = get_store()
    t = Table("collection", "points")
    for name in sorted(store.list_collections()):
        t.add_row(name, str(store.count(name)))
    console.print(t)


@store_app.command("migrate")
def store_migrate(
    collections: list[str] | None = typer.Argument(None, help="Collections to copy (default: all in the source)"),
    source: str = typer.Option("data/qdrant", "--from", help="Embedded Qdrant directory to read from"),
    batch: int = typer.Option(512, "--batch", help="Points per upsert"),
    replace: bool = typer.Option(False, "--replace", help="Drop the target collection first if it exists"),
) -> None:
    """Copy collections from an embedded Qdrant directory into the configured Qdrant server."""
    import time

    from qdrant_client import QdrantClient
    from qdrant_client import models as qm

    from dfa.config import get_settings
    from dfa.retrieval.store import get_store

    s = get_settings()
    if not s.vector_store.url:
        console.print("[red]no server configured[/]: set DFA_QDRANT_URL (or vector_store.url) to the target server first")
        raise typer.Exit(1)
    src_path = s.resolve(source)
    if not (src_path / "meta.json").exists():
        console.print(f"[red]no embedded store[/] at {src_path}")
        raise typer.Exit(1)
    console.print(f"opening embedded store {src_path} (loads everything into RAM, can take a minute)...")
    src = QdrantClient(path=str(src_path))
    dst = get_store()
    names = collections or sorted(c.name for c in src.get_collections().collections)
    for name in names:
        if not src.collection_exists(name):
            console.print(f"[yellow]skip[/] {name}: not in source")
            continue
        total = src.count(name, exact=True).count
        if dst.client.collection_exists(name):
            if replace:
                dst.client.delete_collection(name)
            else:
                console.print(f"[yellow]skip[/] {name}: already on the server ({dst.count(name)} points; --replace to overwrite)")
                continue
        params = src.get_collection(name).config.params
        dst.client.create_collection(name, vectors_config=params.vectors, sparse_vectors_config=params.sparse_vectors)
        dst.create_payload_indexes(name)
        t0, n, offset = time.time(), 0, None
        while True:
            points, offset = src.scroll(name, limit=batch, offset=offset, with_payload=True, with_vectors=True)
            if not points:
                break
            dst.client.upsert(name, [qm.PointStruct(id=p.id, vector=p.vector, payload=p.payload) for p in points], wait=True)
            n += len(points)
            console.print(f"  {name}: {n}/{total}", end="\r")
            if offset is None:
                break
        console.print(f"[green]copied[/] {name}: {n} points in {time.time() - t0:.0f}s")
    src.close()

@user_app.command("add")
def user_add(
    name: str,
    role: str = typer.Option("reader", "--role", help="reader | analyst | admin"),
    cases: str = typer.Option("*", "--cases", help="Comma-separated case ids, or * for all"),
    rotate: bool = typer.Option(False, "--rotate", help="Issue a new token for an existing user"),
) -> None:
    """Create an API user and print its token (shown once; only a hash is stored)."""
    from dfa.api.auth import add_user, users_path

    try:
        token = add_user(name, role, [c.strip() for c in cases.split(",")], rotate=rotate)
    except ValueError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1) from e
    console.print(f"[green]user {name}[/] role={role} cases={cases}\ntoken: [bold]{token}[/]\n(stored hashed in {users_path()}; send as `Authorization: Bearer <token>`)")


@user_app.command("rm")
def user_rm(name: str) -> None:
    """Delete an API user."""
    from dfa.api.auth import remove_user

    console.print(f"[yellow]removed[/] {name}" if remove_user(name) else f"[red]no such user[/] {name}")


@user_app.command("list")
def user_list() -> None:
    """List API users."""
    from dfa.api.auth import list_users

    t = Table("user", "role", "cases", "created", "rotated")
    for u in list_users():
        t.add_row(u["name"], u.get("role", ""), ",".join(u.get("cases", [])), u.get("created", ""), u.get("rotated", ""))
    console.print(t)


@bundle_app.command("build")
def bundle_build(
    out: str = typer.Argument(..., help="Output directory"),
    no_python: bool = typer.Option(False, "--no-python", help="Do not include the Python runtime"),
    no_models: bool = typer.Option(False, "--no-models", help="Do not include the model files"),
) -> None:
    """Collect wheels, Python, models, ATT&CK data and an installer for an air-gapped host (needs network)."""
    from pathlib import Path

    from dfa.bundle import build

    rep = build(Path(out), with_python=not no_python, with_models=not no_models)
    console.print(rep)
    console.print(f"[green]bundle ready[/] in {out} ({rep['bytes'] / 1e9:.1f} GB, {rep['files']} files). Copy it and run install.sh on the offline host.")


@bundle_app.command("verify")
def bundle_verify(path: str) -> None:
    """Check every file of a bundle against MANIFEST.json."""
    from pathlib import Path

    from dfa.bundle import verify

    bad = verify(Path(path))
    console.print("[green]intact[/]" if not bad else f"[red]{len(bad)} file(s) differ[/]: " + ", ".join(bad[:20]))


@bundle_app.command("install")
def bundle_install(path: str, target: str = typer.Option("~/digital_forensic_assistant", "--target")) -> None:
    """Verify a bundle and run its installer (offline)."""
    from pathlib import Path

    from dfa.bundle import install

    raise typer.Exit(install(Path(path), Path(target).expanduser()))


if __name__ == "__main__":
    app()
