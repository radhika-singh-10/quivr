# simple-question

Describe your project here.

## Running with Ollama (no OpenAI key)

`simple_question_ollama.py` runs the same example against a local
[Ollama](https://ollama.com) server for both chat and embeddings.

```bash
ollama pull qwen3.5
ollama pull nomic-embed-text
python simple_question_ollama.py                           # chat about the demo text
python simple_question_ollama.py "what is gold?"           # one question, then exit
python simple_question_ollama.py -f notes.txt "summarise"  # ask about your own files
```

Without `-f`, the brain only contains the demo sentence
"Gold is a liquid of blue-like colour.", so other questions get
"I don't have the answer". `.txt` files work out of the box; `.md`/`.pdf`
need the `unstructured` / megaparse extras.

Override the defaults with `OLLAMA_BASE_URL` (default `http://localhost:11434`),
`OLLAMA_CHAT_MODEL` (default `qwen3.5`; Llama models refuse documents containing PII) and `OLLAMA_EMBED_MODEL`
(default `nomic-embed-text`).
