export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const origin = url.origin;

    const json = (data, status=200) => new Response(JSON.stringify(data), {
      status, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
    const err = (msg, status=400) => json({ error: msg }, status);

    if (method === 'OPTIONS') return new Response(null, { headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization,x-company-slug',
      'Access-Control-Max-Age': '86400'
    }});

    // Public: serve R2 attachments
    if (path.startsWith('/api/attachments/') && method === 'GET') {
      const key = decodeURIComponent(path.replace('/api/attachments/', ''));
      const obj = await env.ATTACHMENTS.get(key);
      if (!obj) return new Response('Not found', { status: 404, headers: { 'Access-Control-Allow-Origin': '*' }});
      const h = new Headers();
      h.set('Content-Type', (obj.httpMetadata && obj.httpMetadata.contentType) || 'application/octet-stream');
      h.set('Cache-Control', 'public, max-age=3600');
      h.set('Access-Control-Allow-Origin', '*');
      return new Response(obj.body, { headers: h });
    }

    // Parse body
    let body = {};
    const ct = request.headers.get('content-type') || '';
    if (['POST','PUT','PATCH'].includes(method) && !ct.includes('multipart') && !ct.includes('image/') && !ct.includes('audio/') && !ct.includes('video/') && !ct.includes('text/plain') && !ct.includes('application/octet-stream') && !ct.includes('application/pdf')) {
      try { body = await request.json(); } catch {}
    }

    // ── Admin PIN login (public) ──
    if (path === '/api/auth/admin-pin' && method === 'POST') {
      const { pin, company_slug } = body;
      if (!pin || !company_slug) return err('Missing fields', 400);
      const row = await env.DB.prepare('SELECT * FROM admins WHERE company_slug=? AND pin=?').bind(company_slug, pin).first();
      if (!row) return err('Invalid PIN', 401);
      const tok = 'adm_' + crypto.randomUUID().replace(/-/g,'');
      await env.KV.put('token:' + tok, JSON.stringify({ role: 'admin', company: company_slug, company_name: row.company_name, plan: row.plan }), { expirationTtl: 86400 * 30 });
      return json({ token: tok, company_name: row.company_name, plan: row.plan });
    }

    // ── Worker PIN login (public) ──
    if (path === '/api/auth/worker-pin' && method === 'POST') {
      const { pin, company_slug } = body;
      if (!pin || !company_slug) return err('Missing fields', 400);
      const worker = await env.DB.prepare('SELECT * FROM workers WHERE pin=? AND company_slug=? AND active=1').bind(pin, company_slug).first();
      if (!worker) return err('Invalid PIN', 401);
      const tok = 'wrk_' + crypto.randomUUID().replace(/-/g,'');
      await env.KV.put('token:' + tok, JSON.stringify({ role: 'worker', worker_id: worker.id, worker_name: worker.name, company: company_slug }), { expirationTtl: 86400 * 7 });
      return json({ token: tok, worker: { id: worker.id, name: worker.name, role: worker.role } });
    }

    // ── INVITE VALIDATE (public) ──
    if (path === '/api/invite/validate' && method === 'GET') {
      const token = url.searchParams.get('token');
      const slug2 = url.searchParams.get('slug') || url.searchParams.get('company_slug') || '';
      if (!token) return err('Missing token');
      const stored = await env.KV.get('invite:' + token);
      if (!stored) return json({ valid: false });
      const inv = JSON.parse(stored);
      const depts = await env.DB.prepare('SELECT * FROM departments WHERE company_slug=? ORDER BY name').bind(inv.slug).all();
      const existingWorkers = await env.DB.prepare('SELECT id, name FROM workers WHERE company_slug=? AND active=1').bind(inv.slug).all();
      return json({ valid: true, company_name: inv.company_name, slug: inv.slug, departments: depts.results || [], workers: (existingWorkers.results || []).map(function(w) { return { name: w.name }; }) });
    }

    // ── WORKER PERMIT SELF-FETCH (public - worker can always get their own permit data) ──
    if (path.match(/^\/api\/workers\/[^/]+\/permit$/) && method === 'GET') {
      const wid3 = path.split('/')[3];
      const slugQ = url.searchParams.get('slug') || url.searchParams.get('company_slug') || '';
      if (!wid3) return err('Missing worker id');
      const whereClause = slugQ
        ? 'SELECT id,name,photo_url,permit_id,permit_front_url,permit_back_url FROM workers WHERE id=? AND company_slug=?'
        : 'SELECT id,name,photo_url,permit_id,permit_front_url,permit_back_url FROM workers WHERE id=?';
      const wrow3 = slugQ
        ? await env.DB.prepare(whereClause).bind(wid3, slugQ).first()
        : await env.DB.prepare(whereClause).bind(wid3).first();
      if (!wrow3) return err('Not found');
      return json({ ok: true, worker: wrow3 });
    }

    // ── RESTORE SESSION (public — worker uses this) ──
    if (path === '/api/restore' && method === 'GET') {
      const restoreToken = url.searchParams.get('token');
      if (!restoreToken) return err('Missing token');
      const dbPub = env.DB;
      const data = await env.KV.get('token:' + restoreToken);
      if (!data) return json({ valid: false, error: 'Link expired or invalid' });
      const td = JSON.parse(data);
      const wrow = await dbPub.prepare('SELECT * FROM workers WHERE id=? AND active=1').bind(td.worker_id).first();
      if (!wrow) return json({ valid: false, error: 'Worker not found' });
      return json({ valid: true, token: restoreToken, worker: { id: wrow.id, name: wrow.name, department: wrow.department, company_name: td.company, photo_url: wrow.photo_url||'', mobile: wrow.mobile||'', permit_id: wrow.permit_id||'', permit_front_url: wrow.permit_front_url||'', permit_back_url: wrow.permit_back_url||'' } });
    }

    // ── PERMIT UPLOADS (public - during registration) ──
    if (path.match(/^\/api\/attach\/permit\/[^/]+\/(front|back)$/) && method === 'POST') {
      const parts2 = path.split('/');
      const workerId = parts2[4];
      const side = parts2[5];
      const slugH = request.headers.get('x-company-slug') || url.searchParams.get('slug') || 'public';
      const ct6 = request.headers.get('content-type') || 'image/jpeg';
      const buf6 = await request.arrayBuffer();
      const ext6 = ct6.includes('png') ? '.png' : '.jpg';
      const key6 = slugH + '/permits/' + workerId + '/' + side + ext6;
      await env.ATTACHMENTS.put(key6, buf6, { httpMetadata: { contentType: ct6 } });
      const permitUrl = url.origin + '/api/attachments/' + encodeURIComponent(key6);
      const col = side === 'front' ? 'permit_front_url' : 'permit_back_url';
      try { await env.DB.prepare('UPDATE workers SET ' + col + '=? WHERE id=?').bind(permitUrl, workerId).run(); } catch(e) {}
      return json({ ok: true, url: permitUrl });
    }

    // ── INVITE REGISTER (public) ──
    if (path === '/api/invite/register' && method === 'POST') {
      const { token, name, pin, department, photo_url, mobile, permit_id } = body;
      if (!token || !name) return err('Missing fields');
      const stored = await env.KV.get('invite:' + token);
      if (!stored) return err('Invalid or expired invite');
      const inv = JSON.parse(stored);
      const slug2 = inv.slug;
      const usePin = pin || ('P' + Math.floor(1000 + Math.random() * 9000));
      const wid = 'W-' + Date.now();
      await env.DB.prepare('INSERT INTO workers (id,name,role,pin,phone,active,company_slug,department,mobile,permit_id) VALUES (?,?,?,?,?,1,?,?,?,?)').bind(wid, name.trim(), 'worker', usePin, '', slug2, department||'', mobile||'', permit_id||'').run();
      if (photo_url) {
        await env.DB.prepare('UPDATE workers SET photo_url=? WHERE id=?').bind(photo_url, wid).run();
      }
      const tok = 'wrk_' + crypto.randomUUID().replace(/-/g,'');
      await env.KV.put('token:' + tok, JSON.stringify({ role: 'worker', worker_id: wid, worker_name: name.trim(), company: slug2 }));
      await env.KV.put('worker_access:' + wid, tok);
      return json({ ok: true, token: tok, worker: { id: wid, name: name.trim() } });
    }

    // ── SELFIE UPLOAD (public) ──
    if (path === '/api/attach/selfie' && method === 'POST') {
      const ct5 = request.headers.get('content-type') || 'image/jpeg';
      const buf = await request.arrayBuffer();
      const selfieSlug = request.headers.get('x-company-slug') || url.searchParams.get('slug') || url.searchParams.get('company_slug') || 'public';
      const selfieWorkerName = request.headers.get('x-worker-name') || 'worker';
      const key = selfieSlug + '/selfies/' + Date.now() + '.jpg';
      await env.ATTACHMENTS.put(key, buf, { httpMetadata: { contentType: ct5 } });
      return json({ ok: true, photo_url: key, url: url.origin + '/api/attachments/' + encodeURIComponent(key) });
    }

    // ── Auth check ──
    const authHeader = request.headers.get('Authorization') || '';
    const token = authHeader.replace('Bearer ', '');
    let auth = null;
    if (token) {
      try { const v = await env.KV.get('token:' + token); if (v) auth = JSON.parse(v); } catch {}
    }
    if (!auth) return err('Unauthorized', 401);

    const db = env.DB;
    const slug = auth.company; // All queries scoped to this slug

    // ── WORKER ACCESS LINK (admin only — needs auth) ──
    if (path.match(/^\/api\/worker-access\/[^/]+$/) && method === 'GET') {
      const wid = path.split('/').pop();
      let tok = await env.KV.get('worker_access:' + wid);
      if (!tok) {
        tok = 'wrk_' + crypto.randomUUID().replace(/-/g,'');
        const wrow = await db.prepare('SELECT * FROM workers WHERE id=? AND company_slug=?').bind(wid, slug).first();
        if (!wrow) return err('Worker not found');
        await env.KV.put('token:' + tok, JSON.stringify({ role: 'worker', worker_id: wid, worker_name: wrow.name, company: slug }));
        await env.KV.put('worker_access:' + wid, tok);
      }
      const workerUrl = 'https://voicetasking-worker.dwhqai.workers.dev/?restore=' + tok + '&slug=' + slug;
      return json({ ok: true, url: workerUrl, token: tok });
    }

    // ── WORKER PROFILE (admin - full permit details) ──
    if (path.match(/^\/api\/workers\/[^/]+\/profile$/) && method === 'GET') {
      const wid2 = path.split('/')[3];
      const wrow2 = await db.prepare('SELECT * FROM workers WHERE id=? AND company_slug=?').bind(wid2, slug).first();
      if (!wrow2) return err('Worker not found');
      // Resolve selfie: check legacy admin-upload path, fall back to DB photo_url
      try {
        const pkey = slug + '/workers/' + wid2 + '/photo';
        const pobj = await env.ATTACHMENTS.head(pkey);
        if (pobj) wrow2.photo_url = origin + '/api/attachments/' + encodeURIComponent(pkey);
        // else keep wrow2.photo_url from DB (set during registration)
      } catch (e) {}
      return json({ ok: true, worker: wrow2 });
    }

    // ── WORKERS ──
    if (path === '/api/workers' && method === 'GET') {
      const rows = await db.prepare('SELECT * FROM workers WHERE company_slug=? AND active=1 ORDER BY name').bind(slug).all();
      const list = rows.results || [];
      const withPhotos = await Promise.all(list.map(async w => {
        // photo_url is stored directly in DB from registration selfie upload
        // Also check R2 for admin-uploaded photos (legacy path)
        try {
          const key = slug + '/workers/' + w.id + '/photo';
          const obj = await env.ATTACHMENTS.head(key);
          if (obj) return { ...w, photo_url: origin + '/api/attachments/' + encodeURIComponent(key) };
        } catch (e) {}
        return { ...w, photo_url: w.photo_url || null };
      }));
      return json(withPhotos);
    }
    if (path === '/api/workers' && method === 'POST') {
      const { name, role, pin, phone, department, mobile } = body;
      const id = 'W-' + Date.now();
      await db.prepare('INSERT INTO workers (id,name,role,pin,phone,active,company_slug,department,mobile) VALUES (?,?,?,?,?,1,?,?,?)').bind(id, name, role||'mechanic', pin||'0000', phone||'', slug, department||'', mobile||'').run();
      return json({ id });
    }
    if (path.match(/^\/api\/workers\/[^/]+$/) && method === 'PUT') {
      const id = path.split('/').pop();
      const { name, role, pin, phone, department, mobile, photo_url } = body;
      await db.prepare('UPDATE workers SET name=?,role=?,pin=?,phone=?,department=?,mobile=? WHERE id=? AND company_slug=?').bind(name, role, pin||'0000', phone||'', department||'', mobile||'', id, slug).run();
      return json({ ok: true });
    }
    if (path.match(/^\/api\/workers\/[^/]+\/photo$/) && method === 'PATCH') {
      const wid4=path.split('/')[3];
      const { photo_url } = body;
      if(!photo_url)return err('Missing photo_url');
      await db.prepare('UPDATE workers SET photo_url=? WHERE id=? AND company_slug=?').bind(photo_url,wid4,slug).run();
      return json({ ok:true });
    }
    if (path.match(/^\/api\/workers\/[^/]+\/permit-id$/) && method === 'PATCH') {
      const wid5=path.split('/')[3];
      const { permit_id } = body;
      await db.prepare('UPDATE workers SET permit_id=? WHERE id=? AND company_slug=?').bind(permit_id||'',wid5,slug).run();
      return json({ ok:true });
    }
    if (path.match(/^\/api\/workers\/[^/]+$/) && method === 'DELETE') {
      const wid = path.split('/').pop();
      await db.prepare('DELETE FROM workers WHERE id=? AND company_slug=?').bind(wid, slug).run();
      return json({ ok: true });
    }
    if (path.match(/^\/api\/workers\/[^/]+\/photo$/) && method === 'POST') {
      const wid = path.split('/')[3];
      const ct2 = request.headers.get('content-type') || 'image/jpeg';
      let buf;
      try { buf = await request.arrayBuffer(); } catch(e) { return err('Failed to read body', 400); }
      const key = slug + '/workers/' + wid + '/photo';
      await env.ATTACHMENTS.put(key, buf, { httpMetadata: { contentType: ct2 } });
      return json({ ok: true, photo_url: origin + '/api/attachments/' + encodeURIComponent(key) });
    }

    // ── TASKS ──
    if (path === '/api/tasks' && method === 'GET') {
      const status = url.searchParams.get('status');
      const worker_id = url.searchParams.get('worker_id');
      const assigned_to = url.searchParams.get('assigned_to');
      let rows;
      if (assigned_to) {
        // Worker portal: fetch only this worker's tasks, include done (pending verify), exclude verified
        rows = await db.prepare("SELECT t.*, w.name as worker_name FROM tasks t LEFT JOIN workers w ON t.assigned_to=w.id WHERE t.assigned_to=? AND t.company_slug=? AND t.status NOT IN ('verified') ORDER BY t.created_at DESC").bind(assigned_to, slug).all();
      } else if (worker_id) {
        rows = await db.prepare("SELECT t.*, w.name as worker_name FROM tasks t LEFT JOIN workers w ON t.assigned_to=w.id WHERE t.assigned_to=? AND t.company_slug=? AND t.status NOT IN ('done','verified') ORDER BY t.created_at DESC").bind(worker_id, slug).all();
      } else if (status === 'verified') {
        rows = await db.prepare("SELECT t.*, w.name as worker_name FROM tasks t LEFT JOIN workers w ON t.assigned_to=w.id WHERE t.status='verified' AND t.company_slug=? ORDER BY t.created_at DESC").bind(slug).all();
      } else if (status) {
        rows = await db.prepare("SELECT t.*, w.name as worker_name FROM tasks t LEFT JOIN workers w ON t.assigned_to=w.id WHERE t.status=? AND t.company_slug=? ORDER BY t.created_at DESC").bind(status, slug).all();
      } else {
        rows = await db.prepare("SELECT t.*, w.name as worker_name FROM tasks t LEFT JOIN workers w ON t.assigned_to=w.id WHERE t.status NOT IN ('verified') AND t.company_slug=? ORDER BY t.created_at DESC").bind(slug).all();
      }
      return json(rows.results || []);
    }
    if (path === '/api/tasks' && method === 'POST') {
      const { title, type, description, assigned_to, due_date, priority, scope, team_name } = body;
      const id = 'TSK-' + Date.now() + Math.floor(Math.random()*1000);
      const wName = assigned_to ? ((await db.prepare('SELECT name FROM workers WHERE id=?').bind(assigned_to).first()) || {}).name || '' : '';
      await db.prepare('INSERT INTO tasks (id,title,type,description,assigned_to,worker_name,status,created_at,due_date,priority,company_slug,scope,team_name) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(id, title, type||'service', description||'', assigned_to||null, wName, 'pending', new Date().toISOString(), due_date||null, priority||'normal', slug, scope||'single', team_name||'').run();
      return json({ id });
    }
    if (path.match(/^\/api\/tasks\/[^/]+$/) && method === 'PATCH') {
      const id = path.split('/').pop();
      const { status, worker_name, issue_notes } = body;
      if (status === 'issue') {
        await db.prepare('UPDATE tasks SET status=?,worker_name=?,issue_notes=? WHERE id=? AND company_slug=?').bind(status, worker_name||'', issue_notes||'', id, slug).run();
      } else {
        await db.prepare('UPDATE tasks SET status=?,worker_name=? WHERE id=? AND company_slug=?').bind(status, worker_name||'', id, slug).run();
      }
      return json({ ok: true });
    }
    if (path.match(/^\/api\/tasks\/[^/]+$/) && method === 'PUT') {
      const id = path.split('/').pop();
      const { title, type, description, assigned_to, due_date, priority, status } = body;
      await db.prepare('UPDATE tasks SET title=?,type=?,description=?,assigned_to=?,due_date=?,priority=?,status=? WHERE id=? AND company_slug=?').bind(title, type||'service', description||'', assigned_to||null, due_date||null, priority||'normal', status||'pending', id, slug).run();
      return json({ ok: true });
    }
    if (path.match(/^\/api\/tasks\/[^/]+$/) && method === 'DELETE') {
      await db.prepare('DELETE FROM tasks WHERE id=? AND company_slug=?').bind(path.split('/').pop(), slug).run();
      return json({ ok: true });
    }

    // ── ATTACHMENTS ──
    if (path.match(/^\/api\/attach\/[^/]+$/) && method === 'POST') {
      const taskId = path.split('/').pop();
      const ct3 = request.headers.get('content-type') || 'audio/webm';
      const buf = await request.arrayBuffer();
      const sender = auth.role === 'admin' ? '_admin' : '_worker';
      const ext = ct3.includes('image') ? '.jpg' : ct3.includes('text') ? '.txt' : ct3.includes('video') ? '.mp4' : '.webm';
      const key = slug + '/tasks/' + taskId + '/' + Date.now() + sender + ext;
      await env.ATTACHMENTS.put(key, buf, { httpMetadata: { contentType: ct3 } });
      return json({ ok: true, key, url: origin + '/api/attachments/' + encodeURIComponent(key) });
    }
    if (path.match(/^\/api\/attach\/[^/]+$/) && method === 'GET') {
      const taskId = path.split('/').pop();
      const prefix = slug + '/tasks/' + taskId + '/';
      const listed = await env.ATTACHMENTS.list({ prefix });
      const files = (listed.objects || []).map(o => ({
        key: o.key,
        url: origin + '/api/attachments/' + encodeURIComponent(o.key),
        size: o.size,
        uploaded: o.uploaded
      }));
      return json(files);
    }
    if (path.match(/^\/api\/attach\/[^/]+\/delete$/) && method === 'POST') {
      const { key } = body;
      if (key && key.startsWith(slug + '/')) await env.ATTACHMENTS.delete(key);
      return json({ ok: true });
    }

    // ── OVERVIEW ──
    if (path === '/api/overview' && method === 'GET') {
      const [taskRow, verifyRow, issueRow] = await Promise.all([
        db.prepare("SELECT COUNT(*) as c FROM tasks WHERE status NOT IN ('done','verified') AND company_slug=?").bind(slug).first(),
        db.prepare("SELECT COUNT(*) as c FROM tasks WHERE status='done' AND company_slug=?").bind(slug).first(),
        db.prepare("SELECT COUNT(*) as c FROM tasks WHERE status='issue' AND company_slug=?").bind(slug).first(),
      ]);
      return json({ total_tasks: (taskRow&&taskRow.c)||0, verify_tasks: (verifyRow&&verifyRow.c)||0, issue_tasks: (issueRow&&issueRow.c)||0 });
    }

    // ── COMPANY LOGO ──
    if (path === '/api/company/logo' && method === 'POST') {
      const ct4 = request.headers.get('content-type') || 'image/jpeg';
      const buf = await request.arrayBuffer();
      const key = slug + '/logo';
      await env.ATTACHMENTS.put(key, buf, { httpMetadata: { contentType: ct4 } });
      return json({ ok: true, logo_url: origin + '/api/attachments/' + encodeURIComponent(key) });
    }
    if (path === '/api/company/logo' && method === 'GET') {
      const key = slug + '/logo';
      const obj = await env.ATTACHMENTS.head(key).catch(() => null);
      const arow = await db.prepare('SELECT company_name FROM admins WHERE company_slug=?').bind(slug).first();
      return json({ logo_url: obj ? origin + '/api/attachments/' + encodeURIComponent(key) : null, company_name: (arow&&arow.company_name)||'' });
    }

    // ── AI BRIEFING ──
    if (path === '/api/ai/morning-briefing' && method === 'POST') {
      const { tasks, parts } = body;
      const taskList = (tasks||[]).map(t => `- ${t.title} (${t.type||'task'}, ${t.priority||'normal'}, ${t.status})`).join('\n') || 'None';
      const partsList = (parts||[]).filter(p => p.qty <= p.min_qty).map(p => `- ${p.name}: ${p.qty} left (min ${p.min_qty})`).join('\n') || 'None';
      const prompt = `You are an operations manager AI for a field service team using Voice Tasking.\n\nToday: ${new Date().toLocaleDateString('en-SG',{weekday:'long',year:'numeric',month:'long',day:'numeric'})}\n\nActive tasks:\n${taskList}\n\nLow stock parts:\n${partsList}\n\nWrite a concise morning briefing with exactly these section headers on their own lines:\nGOOD MORNING\nURGENT\nSERVICE DUE\nACTIVE TASKS\nPARTS\nRECOMMENDATION\n\nBe specific and actionable. 2-3 sentences per section max.`;
      const resp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 800, messages: [{ role: 'user', content: prompt }] })
      });
      const data = await resp.json();
      return json({ briefing: (data.content&&data.content[0]&&data.content[0].text) || '' });
    }


    // ── DEPARTMENTS ──
    if (path === '/api/departments' && method === 'GET') {
      const rows = await db.prepare('SELECT * FROM departments WHERE company_slug=? ORDER BY name').bind(slug).all();
      return json(rows.results || []);
    }
    if (path === '/api/departments' && method === 'POST') {
      const { name } = body;
      if (!name) return err('Name required');
      const id = 'DEP-' + Date.now();
      await db.prepare('INSERT OR IGNORE INTO departments (id,name,company_slug,created_at) VALUES (?,?,?,?)').bind(id, name.trim(), slug, new Date().toISOString()).run();
      return json({ id });
    }
    if (path.match(/^\/api\/departments\/[^/]+$/) && method === 'DELETE') {
      await db.prepare('DELETE FROM departments WHERE id=? AND company_slug=?').bind(path.split('/').pop(), slug).run();
      return json({ ok: true });
    }

    // ── INVITE GENERATE (admin) ──
    if (path === '/api/invite/generate' && method === 'POST') {
      if (auth.role !== 'admin') return err('Forbidden', 403);
      const token = crypto.randomUUID().replace(/-/g,'');
      const depts = await db.prepare('SELECT * FROM departments WHERE company_slug=? ORDER BY name').bind(slug).all();
      const adminRow = await db.prepare('SELECT company_name FROM admins WHERE company_slug=?').bind(slug).first();
      await env.KV.put('invite:' + token, JSON.stringify({ slug, company_name: (adminRow&&adminRow.company_name)||slug }), { expirationTtl: 86400 * 30 });
      const inviteUrl = 'https://voicetasking-worker.dwhqai.workers.dev/?invite=' + token + '&slug=' + slug;
      return json({ invite_url: inviteUrl, token });
    }

    // ── INVITE VALIDATE (public — before auth check, handled below) ──
    // ── INVITE REGISTER (public — before auth check, handled below) ──

    // ── BROADCASTS (Notice Board) ──
    if (path === '/api/broadcasts' && method === 'GET') {
      try {
        const rows = await db.prepare('SELECT * FROM broadcasts WHERE company_slug=? ORDER BY created_at DESC').bind(slug).all();
        return json(rows.results || []);
      } catch(e2) { return err('DB error: ' + e2.message, 500); }
    }
    if (path === '/api/broadcasts' && method === 'POST') {
      try {
        const { title, message, attachment_url, attachment_type } = body;
        if (!title) return err('Title required');
        const count = await db.prepare('SELECT COUNT(*) as c FROM broadcasts WHERE company_slug=?').bind(slug).first();
        if (((count && count.c) || 0) >= 20) return err('Board full. Delete a post first.', 400);
        const id = 'BRD-' + Date.now();
        await db.prepare('INSERT INTO broadcasts (id,title,message,attachment_url,attachment_type,company_slug,created_at) VALUES (?,?,?,?,?,?,?)').bind(id, title, message||'', attachment_url||'', attachment_type||'', slug, new Date().toISOString()).run();
        return json({ id });
      } catch(e2) { return err('DB error: ' + e2.message, 500); }
    }
    if (path.match(/^\/api\/broadcasts\/[^/]+\/read$/) && method === 'POST') {
      return json({ ok: true });
    }
    if (path.match(/^\/api\/broadcasts\/attachment$/) && method === 'POST') {
      const ct = request.headers.get('content-type') || 'image/jpeg';
      const buf = await request.arrayBuffer();
      const ext = ct.includes('pdf') ? '.pdf' : '.jpg';
      const key = slug + '/broadcasts/' + Date.now() + ext;
      await env.ATTACHMENTS.put(key, buf, { httpMetadata: { contentType: ct } });
      return json({ url: origin + '/api/attachments/' + encodeURIComponent(key) });
    }
    if (path.match(/^\/api\/broadcasts\/[^/]+$/) && method === 'DELETE') {
      const id = path.split('/').pop();
      const post = await db.prepare('SELECT attachment_url FROM broadcasts WHERE id=? AND company_slug=?').bind(id, slug).first();
      if (post && post.attachment_url) {
        const key = slug + '/broadcasts/' + id;
        await env.ATTACHMENTS.delete(key).catch(() => {});
      }
      await db.prepare('DELETE FROM broadcasts WHERE id=? AND company_slug=?').bind(id, slug).run();
      return json({ ok: true });
    }

    // ── COMPANY SETTINGS ──
    if (path === '/api/company/settings' && method === 'GET') {
      const row = await db.prepare('SELECT industry FROM admins WHERE company_slug=?').bind(slug).first();
      const presetId = await env.KV.get('settings:preset:' + slug) || '';
      return json({ industry: (row && row.industry) || '', preset_id: presetId });
    }
    if (path === '/api/company/settings' && method === 'POST') {
      const { industry, preset_id, company_name } = body;
      await db.prepare('UPDATE admins SET industry=? WHERE company_slug=?').bind(industry || '', slug).run();
      if (company_name !== undefined) await db.prepare('UPDATE admins SET company_name=? WHERE company_slug=?').bind(company_name, slug).run();
      if (preset_id !== undefined) await env.KV.put('settings:preset:' + slug, preset_id);
      return json({ ok: true });
    }

    // ── PRESETS ──
    if (path === '/api/presets' && method === 'GET') {
      const raw = await env.KV.get('industry_presets');
      const presets = raw ? JSON.parse(raw) : [];
      return json(presets);
    }
    if (path === '/api/presets' && method === 'POST') {
      // DWHQ admin only — add/replace a preset
      if (auth.role !== 'admin') return err('Forbidden', 403);
      const presets = JSON.parse(await env.KV.get('industry_presets') || '[]');
      const p = body;
      const idx = presets.findIndex(x => x.id === p.id);
      if (idx >= 0) presets[idx] = p; else presets.push(p);
      await env.KV.put('industry_presets', JSON.stringify(presets));
      return json({ ok: true });
    }
    if (path === '/api/industry-preview' && method === 'POST') {
      const { preset_id } = body;
      const raw = await env.KV.get('industry_presets');
      const presets = raw ? JSON.parse(raw) : [];
      const preset = presets.find(p => p.id === preset_id);
      if (!preset) return err('Preset not found');
      const apiKey = env.ANTHROPIC_API_KEY || '';
      if (!apiKey) return json({ summary: 'AI preview unavailable — API key not configured.', task_types: preset.task_types });
      const prompt = 'You are helping configure a workforce task management system for a ' + preset.ai_context + '. In 2-3 sentences, describe what kind of daily operations and field tasks this business typically manages. Then list the most common task categories. Be specific and practical. Keep it concise.';
      const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 200, messages: [{ role: 'user', content: prompt }] })
      });
      const aiData = await aiRes.json();
      const summary = (aiData.content && aiData.content[0] && aiData.content[0].text) || 'Preview unavailable.';
      return json({ summary, task_types: preset.task_types, name: preset.name });
    }

    // ── AI GENERATE TASKS ──
    if (path === '/api/ai/generate-tasks' && method === 'POST') {
      const { objective, industry } = body;
      if (!objective) return err('Objective required');
      const systemPrompt = 'You are a task breakdown assistant for a ' + (industry || 'general') + ' business. Given a job objective, generate a JSON array of specific, actionable tasks. Each task has: title (short, specific action), type (one of: service, delivery, inspection, stocktake, other), description (one sentence of details). Return ONLY valid JSON array, no markdown, no explanation. Generate 3-8 tasks depending on complexity.';
      const apiKey = env.ANTHROPIC_API_KEY || '';
      if (!apiKey) return err('AI not configured');
      const aiResp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({
          model: 'claude-sonnet-4-20250514',
          max_tokens: 1024,
          messages: [{ role: 'user', content: 'Job objective: ' + objective }],
          system: systemPrompt
        })
      });
      const aiData = await aiResp.json();
      const text = (aiData.content && aiData.content[0] && aiData.content[0].text) || '[]';
      try {
        var tasks = JSON.parse(text.replace(/```json|\n|```/g, '').trim());
        return json({ tasks: tasks });
      } catch(pe) {
        return err('AI response parse error: ' + pe.message);
      }
    }

    // ── ADMIN MANAGEMENT (add new client) ──
    if (path === '/api/admin/clients' && method === 'POST') {
      if (auth.role !== 'admin') return err('Forbidden', 403);
      const { company_slug: newSlug, company_name, pin, plan } = body;
      if (!newSlug || !company_name || !pin) return err('Missing fields', 400);
      const id = 'ADM-' + Date.now();
      await db.prepare('INSERT INTO admins (id,company_slug,pin,plan,company_name) VALUES (?,?,?,?,?)').bind(id, newSlug, pin, plan||'standard', company_name).run();
      return json({ ok: true, id });
    }

    return err('Not found', 404);
  }
};
