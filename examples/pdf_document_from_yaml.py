# Copyright (c) Lineaje, Inc. All rights reserved.
# gr_check() POSTs to GR_SERVICE_URL+/enforce; fail-open unless GRBlockedError.
class GRBlockedError(Exception):
    def __init__(self, policy_id, reason):
        self.policy_id, self.reason = policy_id, reason
        super().__init__("Guardrail block for policy %r: %s" % (policy_id, reason))

def gr_check(data, source_type, destination_type, tenant_id="", timeout=5.0, **context):
    import json as _j, logging as _lg, os as _os, urllib.error as _ue, urllib.request as _ur
    _log = _lg.getLogger("lineaje.gr_client")
    url = _os.environ.get("GR_SERVICE_URL", "")
    if not url:
        return data
    tid = tenant_id or _os.environ.get("GR_TENANT_ID", "")
    bearer = _os.environ.get("GR_BEARER_TOKEN") or _os.environ.get("LINEAJE_PAT_TOKEN") or _os.environ.get("LINEAJE_PAT", "")
    hop_label = source_type + "->" + destination_type
    params_key = "out_params" if destination_type == "agent" else "in_params"
    try:
        headers = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        body = {"source_type": source_type, "destination_type": destination_type, params_key: {"data": data}}
        for _k, _v in context.items():
            if _v:
                body[_k] = _v
        if tid:
            body["tenant_id"] = tid
        req = _ur.Request(url.rstrip("/") + "/enforce", data=_j.dumps(body).encode(), headers=headers, method="POST")
        with _ur.urlopen(req, timeout=timeout) as resp:
            result = _j.loads(resp.read())
    except Exception as exc:
        if isinstance(exc, _ue.HTTPError) and exc.code == 403:
            try: detail = _j.loads(exc.read()).get("detail", {})
            except Exception: detail = {}
            blocked_by = detail.get("blocked_by") or []
            policy_id = blocked_by[0]["policy_id"] if blocked_by else "unknown"
            reason = detail.get("message", "Request denied by policy enforcement.")
            _log.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
            if _os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
                return data
            raise GRBlockedError(policy_id, reason)
        _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        return data
    if result.get("status") == "escalate":
        _log.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    return result.get("result", {}).get("data", data)
import asyncio
import logging
import os
from pathlib import Path

import dotenv
from quivr_core import Brain
from quivr_core.rag.entities.config import AssistantConfig
from rich.traceback import install as rich_install

ConsoleOutputHandler = logging.StreamHandler()

logger = logging.getLogger("quivr_core")
logger.setLevel(logging.DEBUG)
try:
    ConsoleOutputHandler = gr_check(ConsoleOutputHandler, "agent", "log", site_id='site:sha256:84f9bd695c0d8fd619daf296204a284a4207a6e342bfb4ed7dcee8598adeca61')
except Exception as _gr_exc:
    if type(_gr_exc).__name__ == "GRBlockedError": raise
    ConsoleOutputHandler = ConsoleOutputHandler
    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
logger.addHandler(ConsoleOutputHandler)


logger = logging.getLogger("megaparse")
logger.setLevel(logging.DEBUG)
try:
    ConsoleOutputHandler = gr_check(ConsoleOutputHandler, "agent", "log", site_id='site:sha256:84f9bd695c0d8fd619daf296204a284a4207a6e342bfb4ed7dcee8598adeca61')
except Exception as _gr_exc:
    if type(_gr_exc).__name__ == "GRBlockedError": raise
    ConsoleOutputHandler = ConsoleOutputHandler
    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
logger.addHandler(ConsoleOutputHandler)


# Install rich's traceback handler to automatically format tracebacks
rich_install()


async def main():
    file_path = [
        Path("data/YamEnterprises_Monotype Fonts Plan License.US.en 04.0 (BLP).pdf")
    ]
    file_path = [
        Path(
            "data/YamEnterprises_Monotype Fonts Plan License.US.en 04.0 (BLP) reduced.pdf"
        )
    ]

    config_file_name = (
        "/Users/jchevall/Coding/quivr/backend/core/tests/rag_config_workflow.yaml"
    )

    assistant_config = AssistantConfig.from_yaml(config_file_name)
    # megaparse_config = find_nested_key(config, "megaparse_config")
    megaparse_config = assistant_config.ingestion_config.parser_config.megaparse_config
    megaparse_config.llama_parse_api_key = os.getenv("LLAMA_PARSE_API_KEY")

    processor_kwargs = {
        "megaparse_config": megaparse_config,
        "splitter_config": assistant_config.ingestion_config.parser_config.splitter_config,
    }

    brain = await Brain.afrom_files(
        name="test_brain",
        file_paths=file_path,
        processor_kwargs=processor_kwargs,
    )

    # # Check brain info
    brain.print_info()

    questions = [
        "What is the contact name for Yam Enterprises?",
        "What is the customer phone for Yam Enterprises?",
        "What is the Production Fonts (maximum) for Yam Enterprises?",
        "List the past use font software according to past use term for Yam Enterprises.",
        "How many unique Font Name are there in the Add-On Font Software Section for Yam Enterprises?",
        "What is the maximum number of Production Fonts allowed based on the license usage per term for Yam Enterprises?",
        "What is the number of production fonts licensed by Yam Enterprises? List them one by one.",
        "What is the number of Licensed Monthly Page Views for Yam Enterprises?",
        "What is the monthly licensed impressions (Digital Marketing Communications) for Yam Enterprises?",
        "What is the number of Licensed Applications for Yam Enterprises?",
        "For Yam Enterprises what is the number of applications aggregate Registered users?",
        "What is the number of licensed servers for Yam Enterprises?",
        "When is swap of Production Fonts available in Yam Enterprises?",
        "Who is the primary licensed monotype fonts user for Yam Enterprises?",
        "What is the number of Licensed Commercial Electronic Documents for Yam Enterprises?",
        "How many licensed monotype fonts users can Yam Enterprises have?",
        "How many licensed desktop users can Yam Enterprises have?",
        "Which contract type does Yam Enterprises follow?",
        "What monotype fonts support does Yam Enterprises have?",
        "Which monotype font services onboarding does Yam Enterprises have?",
        "Which Font/User Management does Yam Enterprises have?",
        "What Add-on inventory set did Yam Enterprises pick?",
        "Does Yam Enterprises have Single sign on?",
        "Is there Brand and Licence protection for Yam Enterprises?",
        "Who is the Third Party Payor's contact in Yam Enterprises?",
        "Does Yam Enterprises contract have Company Desktop License?",
        "What is the Number of Swaps Allowed for Yam Enterprises?",
        "When is swap of Production Fonts available in Yam Enterprises?",
    ]

    answers = [
        "Haruko Yamamoto",
        "81 90-1234-5603",
        "300 Production Fonts",
        "Helvetica Regular",
        "7",
        "300 Production Fonts",
        "Yam Enterprises has licensed a total of 105 Production Fonts.",
        "35,000,000",
        "2,500,000",
        "60",
        "40",
        "2",
        "Once per quarter",
        "Haruko Yamamoto",
        "0",
        "100",
        "60",
        "License",
        "Premier",
        "Premier",
        "Premier",
        "Plus",
        "Yes",
        "Yes",
        """
        Name: Yami Enterprises

        Contact: Mei Mei

        Address: 20-22 Tsuki-Tsuki-dori, Tokyo, Japan

        Phone: +81 71-9336-54023

        E-mail: mei.mei@example.com
        """,
        "Yes",
        "One (1) swap per calendar quarter",
        "The swap of Production Fonts will be available one (1) time per calendar quarter by removing Font Software as a Production Font and choosing other Font Software on the Monotype Fonts Platform.",
    ]

    retrieval_config = assistant_config.retrieval_config
    for i, (question, truth) in enumerate(zip(questions, answers, strict=False)):
        chunk = brain.ask(question=question, retrieval_config=retrieval_config)
        try:
            import asyncio as _gr_asyncio
            question = await _gr_asyncio.to_thread(gr_check, question, "agent", "log", site_id='site:sha256:d475d1e22867bfee41f2be2f5cf1116e8eadef2ad2efc1ea7a3071a2208716ec')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            question = question
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        print(
            "\n Question: ", question, "\n Answer: ", chunk.answer, "\n Truth: ", truth
        )
        if i == 5:
            break


if __name__ == "__main__":
    dotenv.load_dotenv()

    # Run the main function in the existing event loop
    asyncio.run(main())
