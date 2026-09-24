# simple-question

Describe your project here.

## Running with Ollama (no OpenAI key)

`simple_question_ollama.py` runs the same example against a local
[Ollama](https://ollama.com) server for both chat and embeddings.

```bash
ollama pull llama3.1
ollama pull nomic-embed-text
python simple_question_ollama.py "what is gold? answer in french"
```

Override the defaults with `OLLAMA_BASE_URL` (default `http://localhost:11434`),
`OLLAMA_CHAT_MODEL` (default `llama3.1`) and `OLLAMA_EMBED_MODEL`
(default `nomic-embed-text`).
