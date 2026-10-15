import re
from enum import Enum

import yaml
from pydantic import BaseModel, field_validator


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


# Model card / technical documentation for the GPAI model used below.
# See MODEL_CARD_URL for details on capabilities, limitations, and intended use.
MODEL_CARD_URL = "https://openai.com/research/gpt-4o"  # GPT-4o model card


class MegaparseBaseConfig(BaseModel):
    @classmethod
    def from_yaml(cls, file_path: str):
        # Load the YAML file
        with open(file_path, "r") as stream:
            config_data = yaml.safe_load(stream)

        # Instantiate the class using the YAML data
        return cls(**config_data)


_ai_app_sec_006_DISAPPROVED_PATTERNS = [
    "deepseekchat",
    "deepseekr1",
    "deepseekr1distillllama70b",
    "deepseekreasoner",
]


def _ai_app_sec_006_normalize(name: str) -> str:
    """Normalize a model identifier for registry comparison."""
    return re.sub(r"[\s\-_\.:\u0000-\u001f]", "", name).lower()


class MegaparseConfig(MegaparseBaseConfig):
    method: ParserType = ParserType.UNSTRUCTURED
    strategy: StrategyEnum = StrategyEnum.FAST
    check_table: bool = False
    parsing_instruction: str | None = None
    model_name: str = "claude-3-5-sonnet-20241022"

    @field_validator("model_name")
    @classmethod
    def _ai_app_sec_006_check_model_not_disapproved(cls, v: str) -> str:
        """Reject models that appear on the organization's disapproved list."""
        normalized = _ai_app_sec_006_normalize(v)
        for pattern in _ai_app_sec_006_DISAPPROVED_PATTERNS:
            if pattern in normalized:
                raise ValueError(
                    f"Model '{v}' is on the organization's disapproved list "
                    "and cannot be used."
                )
        return v
