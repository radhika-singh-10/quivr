from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from quivr_core import Brain
from quivr_core.rag.entities.config import LLMEndpointConfig
from quivr_core.llm.llm_endpoint import LLMEndpoint
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

import re


def sanitize_llm_response(response: str) -> str:
    """Remove lines containing dynamic code execution primitives from LLM output."""
    dangerous_patterns = [
        r'\beval\s*\(',           # Python/JS eval(
        r'\bexec\s*\(',           # Python exec(
        r'\bsubprocess\s*\..*shell\s*=\s*True',  # subprocess(shell=True)
        r'\bos\.system\s*\(',     # os.system(
        r'\bos\.popen\s*\(',      # os.popen(
        r'\beval\s+["\']',        # bash eval "..." or eval '...'
        r'^\s*eval\s+\S',         # bash eval <arg>
        r'\bFunction\s*\(',       # JS new Function(
        r'\bsetTimeout\s*\(\s*["\']',   # JS setTimeout with string
        r'\bsetInterval\s*\(\s*["\']',  # JS setInterval with string
    ]
    combined = re.compile('|'.join(dangerous_patterns), re.IGNORECASE)
    sanitized_lines = [
        line for line in response.splitlines()
        if not combined.search(line)
    ]
    return '\n'.join(sanitized_lines)


INJECTION_PATTERNS = [
    r"ignore (all |previous |above |prior )?instructions",
    r"disregard (all |previous |above |prior )?instructions",
    r"forget (all |previous |above |prior )?instructions",
    r"you are now",
    r"act as",
    r"pretend (to be|you are)",
    r"jailbreak",
    r"do anything now",
    r"override (your |all )?(previous |prior )?instructions",
    r"system prompt",
    r"<\s*system\s*>",
    r"\[system\]",
    r"###\s*instruction",
    r"\{\{.*\}\}",
]


def sanitize_input(text: str) -> str:
    """Detect and block prompt injection attempts in user input."""
    import re
    normalized = text.lower()
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, normalized, re.IGNORECASE):
            raise ValueError(
                f"Prompt injection attempt detected and blocked. "
                f"Matched pattern: '{pattern}'"
            )
    # Strip null bytes and other control characters that may be used to obfuscate injections
    sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return sanitized


if __name__ == "__main__":
    brain = Brain.from_files(
        name="test_brain",
        file_paths=["tests/processor/data/dummy.pdf"],
        llm=LLMEndpoint(
            llm=ChatOpenAI(model="gpt-4o"),
            llm_config=LLMEndpointConfig(model="gpt-4o"),
        ),
        embedder=OpenAIEmbeddings(model="text-embedding-3-small"),
    )
    # Check brain info
    brain.print_info()

    console = Console()
    console.print(Panel.fit("Ask your brain !", style="bold magenta"))

    while True:
        # Get user input
        question = Prompt.ask("[bold cyan]Question[/bold cyan]")

        # Check if user wants to exit
        if question.lower() == "exit":
            console.print(Panel("Goodbye!", style="bold yellow"))
            break

        try:
            sanitized_question = sanitize_input(question)
        except ValueError as e:
            console.print(f"[bold red]Blocked:[/bold red] {e}")
            console.print("-" * console.width)
            continue
        answer = brain.ask(sanitized_question)
        # Sanitize LLM response to remove dynamic code execution primitives
        sanitized_answer = sanitize_llm_response(answer.answer)
        # Print the answer with typing effect
        console.print(f"[bold green]Quivr Assistant[/bold green]: {sanitized_answer}")

        console.print("-" * console.width)

    brain.print_info()
