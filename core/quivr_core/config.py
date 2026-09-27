import base64
import re
from enum import Enum

import yaml
from pydantic import BaseModel


# MODEL_CARD_URL: Technical documentation and model card for the GPAI model used below.
# Ensure this URL is reviewed before deployment.
MODEL_CARD_URL = "https://openai.com/research/gpt-4o"  # GPT-4o model card / technical documentation


class ParserType(str, Enum):
    """Parser type enumeration."""

    UNSTRUCTURED = "unstructured"
    LLAMA_PARSER = "llama_parser"
    MEGAPARSE_VISION = "megaparse_vision"


class StrategyEnum(str, Enum):
    """Method to use for the conversion"""

    FAST = "fast"
    AUTO = "auto"
    HI_RES = "hi_res"


def _scan_for_prompt_injection(value: str) -> None:
    """Scan a string value for common prompt-injection patterns.

    Raises ValueError if a suspicious pattern is detected.
    """
    # 1. Hidden / override prompt patterns
    prompt_override_pattern = re.compile(
        r"(ignore (all )?(previous|prior|above) instructions"
        r"|system\s*prompt"
        r"|you are now"
        r"|act as"
        r"|disregard"
        r"|forget (all )?(previous|prior|above)"
        r"|new instructions"
        r"|override)",
        re.IGNORECASE,
    )
    if prompt_override_pattern.search(value):
        raise ValueError(
            f"Potential prompt-injection detected (override pattern) in config value: {value!r}"
        )

    # 2. Shell command patterns
    shell_pattern = re.compile(
        r"(\$\(|`[^`]+`|\beval\b|\bexec\b|\bos\.system\b|\bsubprocess\b"
        r"|\brm\s+-rf\b|\bcurl\b|\bwget\b|\bnc\b|\bnetcat\b)",
        re.IGNORECASE,
    )
    if shell_pattern.search(value):
        raise ValueError(
            f"Potential shell command injection detected in config value: {value!r}"
        )

    # 3. Base64-encoded content (heuristic: long alphanum+/= token)
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
    for candidate in b64_pattern.findall(value):
        try:
            decoded = base64.b64decode(candidate).decode("utf-8", errors="replace")
            # Re-check the decoded payload for override patterns
            if prompt_override_pattern.search(decoded) or shell_pattern.search(decoded):
                raise ValueError(
                    f"Potential base64-encoded prompt-injection detected in config value: {value!r}"
                )
        except Exception as exc:
            if "prompt-injection" in str(exc) or "shell command" in str(exc):
                raise
            # Decoding failed — not valid base64, ignore

    # 4. Leetspeak heuristic: excessive digit-for-letter substitutions
    leet_pattern = re.compile(r"[a-zA-Z0-9]*[013457@$!][a-zA-Z0-9]*[013457@$!][a-zA-Z0-9]*")
    leet_density = len(leet_pattern.findall(value))
    if leet_density > 5:
        raise ValueError(
            f"Potential leetspeak / obfuscated prompt-injection detected in config value: {value!r}"
        )


def _sanitize_config(config_data: dict) -> dict:
    """Recursively scan all string values in a config dict for prompt injection."""
    for key, value in config_data.items():
        if isinstance(value, str):
            _scan_for_prompt_injection(value)
        elif isinstance(value, dict):
            _sanitize_config(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    _scan_for_prompt_injection(item)
                elif isinstance(item, dict):
                    _sanitize_config(item)
    return config_data


class MegaparseBaseConfig(BaseModel):
    @classmethod
    def from_yaml(cls, file_path: str):
        # Load the YAML file
        with open(file_path, "r") as stream:
            config_data = yaml.safe_load(stream)

        # Sanitize all string values before using them
        config_data = _sanitize_config(config_data)

        # Instantiate the class using the YAML data
        return cls(**config_data)


class MegaparseConfig(MegaparseBaseConfig):
    method: ParserType = ParserType.UNSTRUCTURED
    strategy: StrategyEnum = StrategyEnum.FAST
    check_table: bool = False
    parsing_instruction: str | None = None
    model_name: str = "claude-3-5-sonnet-20240620"
