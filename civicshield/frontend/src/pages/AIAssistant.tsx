import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Bot, Check, Copy, Download, Loader2, Pencil, Plus, RotateCcw, Search, Send, Square, Trash2, Upload, X } from 'lucide-react';
import { api } from '../api';
import { Badge, Err, Page } from '../components/ui';

const SUGGESTIONS = [
  'Give me an overview of my environment.',
  'Which assets require attention?',
  'Show me the latest critical findings.',
  'What threats affect my assets?',
  'Is recovery ready? Show the last run.',
  'What can I ask you to do?',
];

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function inlineMd(s: string): string {
  return esc(s)
    .replace(/\*\*(.+?)\*\*/g, '<strong class="font-semibold">$1</strong>')
    .replace(/`([^`]+?)`/g, '<code class="rounded bg-black/30 px-1 font-mono text-[0.95em]">$1</code>');
}

/** Minimal safe markdown: escaped HTML, fenced code, headings, lists, paragraphs. */
function renderMd(text: string): string {
  const parts = String(text ?? '').split(/```/);
  return parts.map((part, i) => {
    if (i % 2 === 1) {
      const nl = part.indexOf('\n');
      const lang = nl >= 0 ? part.slice(0, nl).trim() : '';
      const code = (nl >= 0 ? part.slice(nl + 1) : part).replace(/\n$/, '');
      return `<div class="my-1.5 overflow-hidden rounded-md border border-line/70">` +
        (lang ? `<div class="bg-black/30 px-2 py-1 font-mono text-[10px] text-slate-500">${esc(lang)}</div>` : '') +
        `<pre class="overflow-x-auto bg-black/30 p-2 font-mono text-[11.5px] leading-relaxed text-slate-200">${esc(code) || ' '}</pre></div>`;
    }
    return part.split('\n').map((line) => {
      const t = line.trimEnd();
      if (!t.trim()) return '';
      if (/^#{1,3}\s/.test(t)) {
        return `<div class="mb-1 mt-2 text-[12.5px] font-semibold text-slate-100">${inlineMd(t.replace(/^#{1,3}\s/, ''))}</div>`;
      }
      if (/^(\d+[.)]|[-*])\s/.test(t)) {
        return `<div class="flex gap-1.5"><span class="text-accent-soft" aria-hidden="true">•</span><span>${inlineMd(t.replace(/^(\d+[.)]|[-*])\s/, ''))}</span></div>`;
      }
      return `<p class="mb-1 last:mb-0">${inlineMd(t)}</p>`;
    }).join('');
  }).join('');
}

type Msg = { id: number; role: string; content: string; meta: any };
type Conv = { id: number; title: string; preview: string; updated_at: number };

export default function AIAssistant() {
  const [convs, setConvs] = useState<Conv[]>([]);
  const [cid, setCid] = useState<number | null>(null);
  const [msgs, setMsgs] = useState<Msg[]>([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [q, setQ] = useState('');
  const [editing, setEditing] = useState<number | null>(null);
  const [editTitle, setEditTitle] = useState('');
  const [sideOpen, setSideOpen] = useState(false);
  const [copied, setCopied] = useState<number | null>(null);
  const [gone, setGone] = useState(false);
  const [searchParams, setSearchParams] = useSearchParams();
  const abortRef = useRef<AbortController | null>(null);
  const bottomRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLTextAreaElement | null>(null);
  const fileRef = useRef<HTMLInputElement | null>(null);
  const qOnce = useRef(false);

  const loadConvs = useCallback(async (select?: number) => {
    try {
      const list = await api.get('/api/ai/conversations');
      setConvs(list ?? []);
      if (select != null) setCid(select);
      else if (list?.length && select === undefined) { /* keep current */ }
    } catch (e: any) { setErr(String(e?.message ?? e)); }
  }, []);

  const loadConv = useCallback(async (id: number) => {
    try {
      const d = await api.get(`/api/ai/conversations/${id}`);
      setCid(id);
      setMsgs(d.messages ?? []);
      setGone(!!d.expired);
      setErr('');
      setSideOpen(false);
    } catch (e: any) { setErr(String(e?.message ?? e)); }
  }, []);

  useEffect(() => { loadConvs(); }, [loadConvs]);
  useEffect(() => { bottomRef.current?.scrollIntoView({ block: 'end' }); }, [msgs, busy]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        inputRef.current?.focus();
      } else if (e.key === 'Escape') {
        if (sideOpen) setSideOpen(false);
        else abortRef.current?.abort();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [sideOpen]);

  const newChat = async () => {
    try {
      const c = await api.post('/api/ai/conversations', { title: '' });
      setConvs((l) => [c, ...l]);
      setCid(c.id);
      setMsgs([]);
      setGone(false);
      setErr('');
      setSideOpen(false);
      inputRef.current?.focus();
    } catch (e: any) { setErr(String(e?.message ?? e)); }
  };

  const removeConv = async (id: number) => {
    if (!window.confirm('Delete this conversation and its task history?')) return;
    try {
      await api.del(`/api/ai/conversations/${id}`);
      setConvs((l) => l.filter((c) => c.id !== id));
      if (cid === id) { setCid(null); setMsgs([]); }
    } catch (e: any) { setErr(String(e?.message ?? e)); }
  };

  const saveTitle = async (id: number) => {
    const title = editTitle.trim();
    setEditing(null);
    if (!title) return;
    try {
      const c = await api.patch(`/api/ai/conversations/${id}`, { title });
      setConvs((l) => l.map((x) => (x.id === id ? c : x)));
    } catch (e: any) { setErr(String(e?.message ?? e)); }
  };

  const streamMessage = async (id: number, text: string, signal: AbortSignal,
    onChunk: (full: string) => void): Promise<{ full: string; meta: any }> => {
    const url = `/api/ai/conversations/${id}/stream?message=${encodeURIComponent(text)}`;
    const res = await fetch(url, { signal, headers: { 'X-Role': localStorage.getItem('cs_role') ?? 'admin' } });
    if (!res.ok || !res.body) throw new Error(`${res.status} ${res.statusText}`);
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = '', full = '', meta: any = {};
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      const frames = buf.split('\n\n');
      buf = frames.pop() ?? '';
      for (const f of frames) {
        const m = f.match(/^data: (.*)$/m);
        if (!m) continue;
        try {
          const d = JSON.parse(m[1]);
          if (d.chunk) { full += d.chunk; onChunk(full); }
          if (d.meta) meta = d.meta;
        } catch { /* ignore partial frame */ }
      }
    }
    if (!full) throw new Error('empty stream');
    return { full, meta };
  };

  const send = async (text: string) => {
    const body = (text ?? '').trim();
    if (!body || busy) return;
    setErr('');
    let id = cid;
    if (id == null) {
      try {
        const c = await api.post('/api/ai/conversations', { title: body.slice(0, 60) });
        setConvs((l) => [c, ...l]);
        id = c.id;
        setCid(c.id);
        setMsgs([]);
      } catch (e: any) { setErr(String(e?.message ?? e)); return; }
    }
    const userMsg: Msg = { id: -Date.now(), role: 'user', content: body, meta: {} };
    if (id == null) return;
    setMsgs((l) => [...l, userMsg]);
    setInput('');
    if (inputRef.current) inputRef.current.style.height = 'auto';
    setBusy(true);
    const ac = new AbortController();
    abortRef.current = ac;
    const tmpId = -Date.now() - 1;
    setMsgs((l) => [...l, { id: tmpId, role: 'assistant', content: '', meta: { streaming: true } }]);
    try {
      const { full, meta } = await streamMessage(id, body, ac.signal,
        (chunk) => setMsgs((l) => l.map((m) => (m.id === tmpId ? { ...m, content: chunk } : m))));
      setMsgs((l) => l.map((m) => (m.id === tmpId ? { ...m, content: full, meta } : m)));
      loadConvs();
    } catch (e: any) {
      if (/^410\b/.test(String(e?.message ?? e))) {
        setGone(true);
        setMsgs((l) => l.filter((m) => m.id !== tmpId));
        setErr('This conversation expired after 24 hours of inactivity. Start a new chat to continue.');
      } else if (ac.signal.aborted) {
        setMsgs((l) => l.map((m) => (m.id === tmpId ? { ...m, content: m.content || '*Response stopped — reload the conversation to see the full answer.*', meta: {} } : m)));
      } else {
        // Streaming failed (proxy/offline): fall back to the plain JSON endpoint.
        try {
          const r = await api.post(`/api/ai/conversations/${id}/messages`, { content: body });
          setMsgs((l) => l.map((m) => (m.id === tmpId ? { id: r.message.id, role: 'assistant', content: r.message.content, meta: r.message.meta } : m)));
          loadConvs();
        } catch (e2: any) {
          setMsgs((l) => l.filter((m) => m.id !== tmpId));
          setErr(String(e2?.message ?? e?.message ?? e2 ?? e));
        }
      }
    } finally {
      setBusy(false);
      abortRef.current = null;
    }
  };

  const retry = () => {
    const lastUser = [...msgs].reverse().find((m) => m.role === 'user');
    if (lastUser) send(lastUser.content);
  };

  const sendRef = useRef(send);
  sendRef.current = send;
  useEffect(() => {
    const initial = searchParams.get('q');
    if (!qOnce.current && initial) {
      qOnce.current = true;
      setSearchParams({}, { replace: true });
      void sendRef.current(initial);
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps — deep-link handoff, mount only

  const exportConv = async () => {
    if (cid == null) return;
    try {
      const d = await api.get(`/api/ai/conversations/${cid}/export`);
      const blob = new Blob([JSON.stringify(d, null, 2)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `assistant-chat-${cid}.json`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (e: any) { setErr(String(e?.message ?? e)); }
  };

  const importConv = async (file: File) => {
    setErr('');
    try {
      const parsed = JSON.parse(await file.text());
      const c = await api.post('/api/ai/conversations/import', { export: parsed });
      setConvs((l) => [c, ...l]);
      loadConv(c.id);
    } catch (e: any) { setErr(`Import failed: ${String(e?.message ?? e)}`); }
  };

  const followups = useMemo(() => {
    if (busy || gone) return [];
    for (let i = msgs.length - 1; i >= 0; i--) {
      const f = msgs[i]?.meta?.followups;
      if (Array.isArray(f) && f.length) {
        // Only offer follow-ups for the latest assistant answer.
        const laterUser = msgs.slice(i + 1).some((m) => m.role === 'user');
        return laterUser ? [] : f.slice(0, 3);
      }
    }
    return [];
  }, [msgs, busy, gone]);

  const actTask = async (taskId: number, action: 'approve' | 'cancel') => {
    setErr('');
    try {
      await api.post(`/api/ai/tasks/${taskId}/${action}`, {});
      if (cid != null) loadConv(cid);
    } catch (e: any) { setErr(String(e?.message ?? e)); }
  };

  const copy = async (id: number, text: string) => {
    try { await navigator.clipboard.writeText(text); setCopied(id); setTimeout(() => setCopied(null), 1200); }
    catch { setErr('Clipboard unavailable in this browser.'); }
  };

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return convs;
    return convs.filter((c) => c.title.toLowerCase().includes(needle) || c.preview.toLowerCase().includes(needle));
  }, [convs, q]);

  const lastAsset = useMemo(() => {
    for (let i = msgs.length - 1; i >= 0; i--) {
      const r = msgs[i]?.meta?.refs?.asset_id;
      if (r != null) return r;
    }
    return null;
  }, [msgs]);

  const lastTask = (m: Msg) => m.meta?.task as { id: number; type: string; status: string; correlation_id: string } | undefined;

  return (
    <Page title="AI Assistant" crumb="CivicShield / Security Workflow / AI Assistant"
      actions={<span className="text-[11px] text-slate-500">Grounded in live records · writes need approval</span>}>
      {err && <Err msg={err} retry={() => setErr('')} />}
      <div className="grid gap-3 lg:grid-cols-[16rem_1fr]">
        <div className={`${sideOpen ? 'fixed inset-y-0 left-0 z-40 flex w-[min(20rem,86vw)] flex-col bg-rail p-3' : 'hidden'} lg:static lg:flex lg:flex-col`}>
          <div className="mb-2 flex items-center gap-1.5">
            <button className="btn flex-1" onClick={newChat}><Plus size={14} aria-hidden="true" /> New chat</button>
            <button className="btn-sec" aria-label="Import conversation from JSON file"
              title="Import a previously exported chat (JSON)"
              onClick={() => fileRef.current?.click()}><Upload size={14} /></button>
            <input ref={fileRef} type="file" accept="application/json,.json" className="hidden" aria-hidden="true" tabIndex={-1}
              onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ''; if (f) importConv(f); }} />
            <button className="btn-sec lg:hidden" onClick={() => setSideOpen(false)} aria-label="Close history"><X size={14} /></button>
          </div>
          <div className="relative mb-2">
            <Search size={12} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-slate-500" aria-hidden="true" />
            <input className="input pl-7" placeholder="Search conversations" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search conversations" />
          </div>
          <div className="grid max-h-[50vh] gap-1 overflow-y-auto lg:max-h-none" role="list" aria-label="Conversation history">
            {filtered.length === 0 && <p className="py-3 text-center text-[12px] text-slate-500">No conversations yet.</p>}
            {filtered.map((c) => (
              <div key={c.id} role="listitem"
                className={`group flex items-center gap-1 rounded-md border px-2 py-1.5 ${c.id === cid ? 'border-accent/30 bg-accent/10' : 'border-transparent hover:border-line hover:bg-white/[0.035]'}`}>
                {editing === c.id ? (
                  <input className="input min-w-0 flex-1 py-1 text-[12px]" value={editTitle}
                    onChange={(e) => setEditTitle(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') saveTitle(c.id); if (e.key === 'Escape') setEditing(null); }}
                    onBlur={() => saveTitle(c.id)} autoFocus aria-label="Conversation title" />
                ) : (
                  <button className="min-w-0 flex-1 truncate text-left text-[12.5px] text-slate-200" onClick={() => loadConv(c.id)} title={c.preview}>
                    {c.title || 'New conversation'}
                  </button>
                )}
                <button className="shrink-0 rounded p-1 text-slate-600 hover:text-slate-200" aria-label={`Rename conversation ${c.title}`}
                  onClick={() => { setEditing(c.id); setEditTitle(c.title); }}><Pencil size={12} /></button>
                <button className="shrink-0 rounded p-1 text-slate-600 hover:text-red-300" aria-label={`Delete conversation ${c.title}`}
                  onClick={() => removeConv(c.id)}><Trash2 size={12} /></button>
              </div>
            ))}
          </div>
        </div>

        <div className="card flex min-h-[60vh] flex-col">
          {gone && (
            <div className="mb-2 rounded-md border border-amber-300/30 bg-amber-500/[0.07] px-2.5 py-2 text-[12.5px] text-amber-300" role="status">
              This conversation expired after 24 hours of inactivity — history stays readable, but no new messages. Start a new chat to continue.
            </div>
          )}
          <div className="mb-2 flex items-center gap-2">
            <button className="btn-sec lg:hidden" onClick={() => setSideOpen(true)} aria-label="Open history"><Search size={0} />History</button>
            <button className="btn-sec ml-auto" onClick={exportConv} disabled={cid == null} aria-label="Export conversation as JSON">
              <Download size={13} aria-hidden="true" /> Export
            </button>
            {lastAsset != null && (
              <span className="badge border border-line/70 bg-raised/30 !text-slate-300">Context: asset #{lastAsset}</span>
            )}
            <span className="ml-auto flex items-center gap-1.5 text-[11px] text-slate-500">
              <Bot size={13} aria-hidden="true" /> {busy ? 'Working…' : 'Ready'}
            </span>
          </div>

          <div className="grid max-h-[55vh] min-h-[40vh] flex-1 content-start gap-2 overflow-y-auto pr-1 lg:max-h-[calc(100dvh-24rem)]" aria-live="polite" aria-label="Messages">
            {msgs.length === 0 && (
              <div className="grid gap-3 py-6 text-center">
                <Bot size={28} className="mx-auto text-accent-soft" aria-hidden="true" />
                <p className="mx-auto max-w-[34rem] text-[13px] text-slate-300">
                  Hello! I&apos;m your AI assistant. I can help you understand your environment,
                  investigate assets, analyze activity, and perform authorized tasks.
                </p>
                <div className="mx-auto grid w-full max-w-[34rem] gap-1.5 sm:grid-cols-2">
                  {SUGGESTIONS.map((s) => (
                    <button key={s} className="btn-sec justify-start text-left" disabled={busy} onClick={() => send(s)}>{s}</button>
                  ))}
                </div>
              </div>
            )}
            {msgs.map((m) => {
              const task = lastTask(m);
              return (
                <div key={m.id} className={`max-w-full rounded-lg border px-3 py-2 text-[13px] leading-relaxed ${m.role === 'user' ? 'justify-self-end border-accent/30 bg-accent/[0.08] text-slate-100' : 'border-line/70 bg-raised/30 text-slate-300'}`}>
                  <div className="mb-1 flex items-center gap-2">
                    <span className="font-mono text-[10px] uppercase tracking-[0.08em] text-slate-500">{m.role === 'user' ? 'You' : m.role === 'tool' ? 'Tool result' : 'Assistant'}</span>
                    {m.role === 'assistant' && m.meta?.model_used && !m.meta?.streaming && (
                      <span className="rounded border border-line/70 bg-black/20 px-1 py-px font-mono text-[9.5px] text-slate-500" title={m.meta.model_used === 'fallback' ? 'Answered from the offline deterministic template' : 'Drafted by the live model from verified records'}>
                        {m.meta.model_used === 'fallback' ? 'offline template' : m.meta.model_used === 'policy' ? 'access policy' : `model: ${m.meta.model_used}`}
                      </span>
                    )}
                    {m.meta?.streaming && <Loader2 size={11} className="animate-spin text-accent-soft" aria-hidden="true" />}
                    <span className="ml-auto flex items-center gap-1">
                      <button className="rounded p-0.5 text-slate-600 hover:text-slate-200" aria-label="Copy message"
                        onClick={() => copy(m.id, m.content)}>{copied === m.id ? <Check size={12} className="text-emerald-300" /> : <Copy size={12} />}</button>
                      {m.role === 'assistant' && !m.meta?.streaming && (
                        <button className="rounded p-0.5 text-slate-600 hover:text-slate-200" aria-label="Retry response" onClick={retry} disabled={busy}><RotateCcw size={12} /></button>
                      )}
                    </span>
                  </div>
                  {m.role === 'user'
                    ? <p className="whitespace-pre-wrap">{m.content}</p>
                    : <div dangerouslySetInnerHTML={{ __html: renderMd(m.content) }} />}
                  {task && (
                    <div className="mt-2 rounded-md border border-line/70 bg-black/20 px-2 py-1.5">
                      <div className="flex flex-wrap items-center gap-2 text-[11.5px]">
                        <Badge text={task.status.replace(/_/g, ' ')} />
                        <span className="font-mono text-slate-400">{task.type} · {task.correlation_id}</span>
                        {task.status === 'pending_approval' && (
                          <span className="ml-auto flex gap-1.5">
                            <button className="btn px-2 py-1 text-[12px]" style={{ minHeight: 28 }} disabled={busy}
                              onClick={() => actTask(task.id, 'approve')}>Approve</button>
                            <button className="btn-sec px-2 py-1 text-[12px]" style={{ minHeight: 28 }} disabled={busy}
                              onClick={() => actTask(task.id, 'cancel')}>Cancel</button>
                          </span>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
            <div ref={bottomRef} />
          </div>

          <div className="mt-2 border-t border-line/70 pt-2">
            {followups.length > 0 && (
              <div className="mb-1.5 flex flex-wrap gap-1.5" aria-label="Suggested follow-ups">
                {followups.map((s) => (
                  <button key={s} className="btn-sec py-1 text-[11.5px]" disabled={busy || gone} onClick={() => send(s)}>{s}</button>
                ))}
              </div>
            )}
            <div className="flex items-end gap-1.5">
              <textarea ref={inputRef} className="input max-h-36 min-h-[38px] flex-1 resize-none" rows={1}
                placeholder={gone ? 'Conversation expired — start a new chat' : 'Ask about assets, findings, incidents, threats, recovery… (Ctrl+K to focus)'}
                aria-label="Message the assistant" disabled={gone}
                value={input}
                onChange={(e) => { setInput(e.target.value); e.target.style.height = 'auto'; e.target.style.height = `${Math.min(e.target.scrollHeight, 144)}px`; }}
                onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(input); } }} />
              {busy
                ? <button className="btn-sec" aria-label="Stop generating (Esc)" onClick={() => abortRef.current?.abort()}><Square size={14} /></button>
                : <button className="btn" aria-label="Send message" disabled={!input.trim() || gone} onClick={() => send(input)}><Send size={14} /></button>}
            </div>
            <p className="mt-1 text-[10.5px] text-slate-600">Enter to send · Shift+Enter for a new line. Answers cite live records; actions always ask first.</p>
          </div>
        </div>
      </div>
    </Page>
  );
}
