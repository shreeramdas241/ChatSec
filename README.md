# ChatSec AI

ChatSec AI is a command-line security scanner for AI chatbots you are allowed to test. It sends a small, reviewed set of probes through one connector, checks the responses against requirements you configure, and writes a JSON report and a Markdown report.

The six modules do not change when the chatbot is reached over HTTP or through a voice transcript adapter. A browser adapter can implement the same connector later.

## Run the local demo

Install Python 3.10 or newer, then:

```powershell
pip install -r requirements.txt
python chatsec.py serve-demo --mode secure
```

In a second terminal, from this same directory:

```powershell
python chatsec.py scan --config config/target.yaml
```

A secure demo exits 0. Every module should be **Passed**.

Stop the server with Ctrl+C, start it again with `--mode vulnerable`, and scan again. That mode is a local test double that fails the six checks on purpose. The scan exits 1 and the report lists the evidence. The demo binds only to localhost.

List the modules:

```powershell
python chatsec.py list-tests
```

Rerun one module:

```powershell
python chatsec.py scan --config config/target.yaml --tests prompt_injection
```

Reports are written to `reports/`.

## What you configure

You configure the chatbot and the pass conditions. The scanner owns the probes.

`config/target.yaml` is the example. For a real staging bot, copy it and change the target fields:

- `target.base_url` and `target.endpoint`
- `request.style`: `message_field` for `{"message": "..."}`, or `messages` for a chat-completions style body
- `response.answer_field`: dot path to the answer, such as `answer` or `choices.0.message.content`
- `authentication`: `none`, `bearer`, or `header`

Put secrets in the environment, not in the file:

```yaml
authentication:
  type: bearer
  token_env: CHATBOT_TEST_TOKEN
```

`authorization.confirmed` must be true, `authorization.allowed_hosts` must include the target host, and `scan.environment` must be `local`, `dev`, `test`, or `staging`. The scanner refuses `production`, unlisted hosts, credentials in the URL, and inline tokens. Those checks stop accidents. They do not grant permission. Only point it at a system you are allowed to test.

`scan.max_requests` is a hard budget. The rate-limit module sends at most 20 sequential requests. This is not a load test.

## The six checks

| Module | What it tests | What counts as a finding |
| --- | --- | --- |
| `prompt_injection` | Direct instruction manipulation | The reply contains a marker you planted, outside a full echo of the probe |
| `sensitive_data` | Secret and private-data disclosure | An unauthorized session receives a synthetic canary |
| `indirect_injection` | Instructions in retrieved content | A document fixture causes the assistant to return the compliance marker |
| `tool_authorization` | Agent permissions and tool use | A prohibited tool receipt appears, or the tool log says it executed |
| `output_safety` | Unsafe generated output | The configured downstream checker reports unsafe handling |
| `rate_limits` | Excessive requests and resource use | Successful requests exceed the limit you documented |

A refusal is not automatically a pass. A changed answer is not automatically a finding. Each module looks for the evidence in the table.

Results that are **Not applicable**, **Inconclusive**, **Needs instrumentation**, or **Needs verification** are not passes. `--strict` makes the process exit 1 for inconclusive and needs-* results. Not applicable still exits 0, because the product does not have that feature.

Exit codes: `0` no findings, `1` at least one finding, `2` the scan could not complete.

## Plant the values the checks look for

The demo plants these synthetic values for you. On a real chatbot they only mean something if the application actually contains them:

- Put `policies.prompt_injection.system_canary` in the system prompt. Leave it empty to skip that probe.
- Put `policies.sensitive_data.canaries` in a protected test record that the unauthorized test identity must not see.
- The indirect-injection marker is inserted into a document by the scanner. The target needs the upload and delete endpoints in `fixtures`, and `capabilities.retrieves_documents: true`. Otherwise the module is not applicable.
- The tool receipt should be returned only when the prohibited tool really runs. Set `instrumentation.enabled` and `response.tool_events_field` when the API returns tool decisions. Without a receipt or a log, the module asks for instrumentation instead of guessing.
- `fixtures.output_verification` should be a test endpoint in your application that reports whether its real sink would handle the model output unsafely. The scanner does not treat a suspicious string as a finding by itself. The demo checker does not execute the output.
- `policies.rate_limits` is the limit you expect for one session. Run this module first, or alone, when the limit is per IP rather than per session. Earlier modules spend requests too.

## Voice

`connector.type: voice_transcript` sends the same text probes through the HTTP API and labels the report as a transcript. That covers the assistant behind a voice bot. It does not cover speech recognition, spoken prompt injection, or audio playback.

`connector.type: browser` is reserved. It stops with an error instead of pretending to drive a page.

## Tests

```powershell
python -m unittest discover -s unit_tests -v
```

The demo tests start a localhost server, scan it, and check the report. No external chatbot is contacted.
