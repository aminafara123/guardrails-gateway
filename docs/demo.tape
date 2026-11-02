# Renders docs/demo.gif with charmbracelet/vhs (needs vhs, ttyd and ffmpeg on PATH).
# Run from the repo root, with the deps installed in .venv:  vhs docs/demo.tape
# Follows DEMO.md offline path: tests -> gateway on :8000 -> PII redaction -> injection block -> secret egress block.
Output docs/demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1200
Set Height 920
Set Padding 24
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set TypingSpeed 25ms

Hide
Type "VIRTUAL_ENV_DISABLE_PROMPT=1 source .venv/bin/activate"
Enter
Wait@120s
Type "make run >/dev/null 2>&1 &"
Enter
Wait@120s
Type "trap 'kill %1' EXIT"
Enter
Wait@120s
Type "sleep 3"
Enter
Wait@120s
Type "clear"
Enter
Wait@120s
Show
Sleep 500ms

Type "make test"
Sleep 400ms
Enter
Wait@120s
Sleep 2s

Hide
Type "clear"
Enter
Sleep 200ms
Show
Type "curl -s localhost:8000/guard/check -H 'content-type: application/json' -d @samples/requests/guard_check_pii.json | python3 -m json.tool"
Sleep 400ms
Enter
Wait@120s
Sleep 4s

Hide
Type "clear"
Enter
Sleep 200ms
Show
Type "curl -s localhost:8000/v1/chat/completions -H 'content-type: application/json' -d @samples/requests/chat_injection.json | python3 -m json.tool"
Sleep 400ms
Enter
Wait@120s
Sleep 4.5s

Hide
Type "clear"
Enter
Sleep 200ms
Show
Type "curl -s localhost:8000/guard/check -H 'content-type: application/json' -d @samples/requests/guard_check_secret.json | python3 -m json.tool"
Sleep 400ms
Enter
Wait@120s
Sleep 4s

Sleep 1s
