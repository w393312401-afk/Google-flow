"""Durable client submission receipts; observation never creates a generation."""

import hashlib
import json
import re
import time
from urllib.parse import parse_qs, urlsplit
from typing import Any


SCHEMA = """
CREATE TABLE IF NOT EXISTS client_submissions (
    client_submission_id TEXT PRIMARY KEY,
    request_hash TEXT NOT NULL,
    api_model TEXT,
    state TEXT NOT NULL DEFAULT 'pending',
    account_id INTEGER,
    operation_id TEXT,
    project_id TEXT,
    operations TEXT,
    video_url TEXT,
    error TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""


def request_hash(model, prompt, images):
    digest = hashlib.sha256()
    for value in [model.encode(), prompt.encode(), *(images or [])]:
        digest.update(len(value).to_bytes(8, 'big'))
        digest.update(value)
    return digest.hexdigest()


class SubmissionLedger:
    def __init__(self, db):
        self.db = db

    async def reserve(self, submission_id, fingerprint, api_model=None):
        """Atomic INSERT decides which request, if any, may submit upstream."""
        async with self.db._connect(write=True) as con:
            await con.execute(SCHEMA)
            if not await self.db._column_exists(con, 'client_submissions', 'api_model'):
                await con.execute('ALTER TABLE client_submissions ADD COLUMN api_model TEXT')
            cursor = await con.execute(
                "INSERT OR IGNORE INTO client_submissions (client_submission_id, request_hash, api_model) VALUES (?, ?, ?)",
                (submission_id, fingerprint, api_model),
            )
            await con.commit()
            created = cursor.rowcount == 1
        row = await self.get(submission_id)
        return created, row['request_hash'] == fingerprint

    async def get(self, submission_id):
        async with self.db._connect() as con:
            # Compatibility with a running installation before its next startup.
            if not await self.db._table_exists(con, 'client_submissions'):
                return None
            cursor = await con.execute(
                "SELECT * FROM client_submissions WHERE client_submission_id = ?", (submission_id,)
            )
            raw = await cursor.fetchone()
            if raw is None:
                return None
            row = dict(zip([item[0] for item in cursor.description], raw))
            for key in ('operations', 'error'):
                if row.get(key):
                    row[key] = json.loads(row[key])
            return row

    async def update(self, submission_id, **values):
        if not submission_id:
            return
        allowed = {'state', 'account_id', 'operation_id', 'project_id', 'operations', 'video_url', 'error', 'api_model'}
        assert set(values) <= allowed
        async with self.db._connect(write=True) as con:
            assignments, args = [], []
            for key, value in values.items():
                assignments.append(key + ' = ?')
                args.append(json.dumps(value, ensure_ascii=False) if key in {'operations', 'error'} and value is not None else value)
            await con.execute(
                "UPDATE client_submissions SET " + ', '.join(assignments) + ", updated_at = CURRENT_TIMESTAMP WHERE client_submission_id = ?",
                (*args, submission_id),
            )
            await con.commit()

    async def accepted(self, submission_id, account_id, project_id, operations):
        if not submission_id:
            return
        operation = operations[0] if operations else {}
        operation_id = (operation.get('operation') or {}).get('name') or operation.get('name')
        await self.update(submission_id, account_id=account_id, project_id=project_id,
                          operation_id=operation_id, operations=operations)

    async def backfill_legacy(self, submission_id, request_log_id, expected_prompt_hash):
        """Explicit local migration using one unique, exact original prompt receipt.

        Caller supplies the historical log id and its SPARK journal prompt hash.
        Ambiguous or truncated prompts and generic failures remain unresolved.
        """
        async with self.db._connect() as con:
            cursor = await con.execute('SELECT id,token_id,request_body,response_body FROM request_logs')
            matches = []
            for raw in await cursor.fetchall():
                try:
                    request = json.loads(raw[2])
                    response = json.loads(raw[3])
                    prompt = request['prompt']
                    if hashlib.sha256(prompt.encode()).hexdigest() == expected_prompt_hash:
                        matches.append((raw, request, response))
                except (ValueError, TypeError, KeyError):
                    continue
        if len(matches) != 1 or matches[0][0][0] != request_log_id:
            raise ValueError('Legacy request does not uniquely match the original SPARK prompt hash')
        raw, request, response = matches[0]
        created, _ = await self.reserve(submission_id, 'legacy:' + expected_prompt_hash, request.get('model'))
        if not created:
            raise ValueError('Legacy submission already has a durable receipt')
        await self.update(submission_id, account_id=raw[1])
        error = response.get('error')
        if isinstance(error, dict) and error.get('upstream_accepted') is True and error.get('task_id'):
            task = await self.db.get_task(error['task_id'])
            if task is None or task.token_id != raw[1] or hashlib.sha256(task.prompt.encode()).hexdigest() != expected_prompt_hash:
                raise ValueError('Original Flow operation does not match the legacy request')
            await self.accepted(submission_id, raw[1], None, [{
                'name': task.task_id, 'operation': {'name': task.task_id},
                'mediaName': task.task_id, 'frontendRpc': 'jwpduf',
                'status': 'MEDIA_GENERATION_STATUS_ACTIVE',
            }])
        elif isinstance(error, str) and re.fullmatch(
            r'生成失败: Flow frontend RPC rejected: rpc=(?:YhhmEf|eb1hJf|nprQif), error=PUBLIC_ERROR_UNUSUAL_ACTIVITY(?:_TOO_MUCH_TRAFFIC)?', error
        ):
            await self.update(submission_id, state='refused', error={
                'code': 'submission_rejected', 'message': error, 'reason': 'unusual_activity',
                'client_submission_id': submission_id, 'submission_pending': False, 'upstream_accepted': False,
            })
        return self.public(submission_id, await self.get(submission_id))

    @staticmethod
    def public(submission_id, row):
        if row is None:
            return {'client_submission_id': submission_id, 'state': 'not_found',
                    'submission_pending': True, 'upstream_accepted': None}
        state = row['state']
        result: dict[str, Any] = {
            'client_submission_id': submission_id, 'state': state,
            'submission_pending': state not in {'confirmed', 'refused', 'failed'},
            'upstream_accepted': True if row.get('operation_id') or state in {'confirmed', 'failed'} else (False if state == 'refused' else None),
        }
        for key in ('operation_id', 'account_id', 'video_url', 'error', 'api_model'):
            if row.get(key) is not None:
                result[key] = row[key]
        if row.get('operation_id'):
            result['upstream_task_id'] = row['operation_id']
        if row.get('account_id') is not None:
            result['upstream_account_id'] = row['account_id']
        return result

    async def capture(self, submission_id, payload):
        """Persist the authoritative result before it is sent to a stream client."""
        if not submission_id:
            return payload
        row = await self.get(submission_id)
        error = payload.get('error')
        if isinstance(error, dict):
            if row['state'] == 'confirmed':
                # A later local logging/disconnect error cannot undo an already delivered video.
                payload['submission'] = self.public(submission_id, row)
                return payload
            error['client_submission_id'] = submission_id
            for key in ('operation_id', 'account_id'):
                if row.get(key) is not None:
                    error.setdefault(key, row[key])
            proven_refusal = (
                error.get('code') in {'no_available_token', 'submission_not_started', 'submission_rejected'}
                and error.get('submission_pending') is False
                and error.get('upstream_accepted') is False
                and not row.get('operation_id')
                and not error.get('operation_id')
            )
            proven_failure = (
                error.get('code') == 'video_generation_failed'
                and error.get('submission_pending') is False
                and error.get('upstream_accepted') is True
                and bool(row.get('operation_id'))
                and error.get('operation_id') == row['operation_id']
            )
            if proven_refusal:
                # Only the handler's explicit non-submission proof permits refusal.
                state = 'refused'
            elif proven_failure:
                state = 'failed'
            else:
                state = 'pending'
                error['submission_pending'] = True
                error['upstream_accepted'] = True if row.get('operation_id') else None
            await self.update(submission_id, state=state, error=error)
        else:
            text = ''.join(
                str((choice.get('delta') or choice.get('message') or {}).get('content') or '')
                for choice in payload.get('choices', [])
            )
            # The actual video output is the sole completion evidence.
            match = re.search(r"<video[^>]+src=['\"]([^'\"]+)['\"]", text, re.I)
            if match:
                await self.update(submission_id, state='confirmed', video_url=match.group(1), error=None)
        return payload

    async def observe(self, submission_id, handler):
        row = await self.get(submission_id)
        if row is None or row['state'] in {'refused', 'failed'} or not row.get('operation_id'):
            return self.public(submission_id, row)
        if row['state'] == 'confirmed':
            try:
                expiry = int(parse_qs(urlsplit(row.get('video_url') or '').query).get('Expires', ['0'])[0])
            except ValueError:
                expiry = 0
            if not expiry or expiry > time.time() + 60:
                return self.public(submission_id, row)
        token = await self.db.get_token(row['account_id'])
        if token is None:
            return self.public(submission_id, row)
        try:
            checked = await handler.flow_client.check_video_status(
                token.at, row['operations'], token_id=token.id, google_cookies=token.google_cookies,
            )
            operation = (checked.get('operations') or [{}])[0]
            checked_id = operation.get('name') or (operation.get('operation') or {}).get('name')
            if checked_id != row['operation_id']:
                # Never attribute an unrelated media result to this client receipt.
                return self.public(submission_id, row)
            status = str(operation.get('status') or '')
            url = handler.flow_client._find_flow_content_url(checked, 'video')
            if status == 'MEDIA_GENERATION_STATUS_SUCCESSFUL' and url:
                await self.update(submission_id, state='confirmed', video_url=url, error=None)
                await self.db.update_task(row['operation_id'], status='completed', progress=100, result_urls=[url],
                                          error_message='', completed_at=time.time())
            elif status == 'MEDIA_GENERATION_STATUS_FAILED' or status.startswith('MEDIA_GENERATION_STATUS_ERROR'):
                error = (operation.get('operation') or {}).get('error') or {}
                await self.update(submission_id, state='failed', error={
                    'code': 'video_generation_failed', 'message': error.get('message') or status,
                    'submission_pending': False, 'upstream_accepted': True,
                })
            else:
                await self.update(submission_id, operations=checked.get('operations') or row['operations'])
        except Exception as exc:
            # Credential/network failure is an observation failure, never cancellation.
            reason = 'poll_auth_failed' if re.search(r'401|UNAUTHENTICATED', str(exc), re.I) else 'poll_failed'
            if row['state'] == 'confirmed':
                # Expired delivery URL needs a new read, but prior paid success is settled.
                return {**self.public(submission_id, row), 'delivery_pending': True, 'video_url': None}
            await self.update(submission_id, error={
                'code': 'video_status_unknown', 'message': '原视频状态暂未确认，请恢复查询后再处理',
                'reason': reason, 'submission_pending': True, 'upstream_accepted': True,
            })
        return self.public(submission_id, await self.get(submission_id))
