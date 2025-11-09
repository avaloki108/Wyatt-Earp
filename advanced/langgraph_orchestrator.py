"""LangGraph-based orchestration for the advanced multi-agent reasoning engine."""

from __future__ import annotations

from dataclasses import dataclass
import json
import copy
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

try:  # LangGraph is an optional dependency during import time in some environments
    from langgraph.graph import StateGraph, START, END
    from langgraph.checkpoint.memory import MemorySaver
except ImportError as exc:  # pragma: no cover - handled gracefully by caller
    raise


@dataclass
class AgentRun:
    """Structured record of a single agent execution within the DAG."""

    name: str
    role: str
    temperature: float
    prompt: str
    raw_response: Any
    parsed_response: Any
    decision: Optional[str] = None


@dataclass
class LangGraphExecutionResult:
    """Aggregate result returned after executing the LangGraph DAG."""

    agent_runs: List[AgentRun]
    shared_state: Dict[str, Any]
    final_decision: str
    iterations: int


class LangGraphOrchestrator:
    """Encapsulates the LangGraph DAG used for advanced multi-agent reasoning."""

    DEFAULT_CONFIG_PATH = Path(__file__).parent / "prompt_chain_config.yaml"

    def __init__(self, llm_client: Any, config_path: Optional[str] = None):
        self.llm_client = llm_client
        self.config = self._load_config(config_path)
        self.langgraph_config = self.config.get("langgraph", {})
        self.agents_config = self.langgraph_config.get("agents", {})
        self.max_rewrites = int(self.langgraph_config.get("max_rewrites", 1))
        self.default_model = self.langgraph_config.get("model", "gpt-4-turbo")

        self._graph = self._build_graph()
        # MemorySaver keeps the shared state available across conditional loops
        self._app = self._graph.compile(checkpointer=MemorySaver())

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def run(self,
            contract_code: str,
            static_analysis_results: Optional[Dict[str, Any]],
            contract_type: str = "unknown") -> LangGraphExecutionResult:
        """Execute the LangGraph DAG for the supplied contract context."""

        initial_state: Dict[str, Any] = {
            "contract_code": contract_code,
            "contract_type": contract_type,
            "static_analysis": static_analysis_results or {},
            "shared_memory": self._initial_shared_memory(),
            "agent_reports": [],
            "iteration": 0,
            "rewrite_count": 0,
        }

        final_state = self._app.invoke(initial_state)

        agent_runs = [
            AgentRun(
                name=report.get("agent", "unknown"),
                role=report.get("role", report.get("agent", "unknown")),
                temperature=report.get("temperature", 0.0),
                prompt=report.get("prompt", ""),
                raw_response=report.get("raw_response"),
                parsed_response=report.get("parsed"),
                decision=report.get("decision"),
            )
            for report in final_state.get("agent_reports", [])
        ]

        final_assessment = final_state.get("shared_memory", {}).get("final_assessment", {})
        final_decision = final_assessment.get("status", "undetermined")

        return LangGraphExecutionResult(
            agent_runs=agent_runs,
            shared_state=final_state.get("shared_memory", {}),
            final_decision=final_decision,
            iterations=final_state.get("iteration", 0),
        )

    # ------------------------------------------------------------------
    # Graph construction helpers
    # ------------------------------------------------------------------
    def _build_graph(self) -> StateGraph:
        graph: StateGraph = StateGraph(dict)

        graph.add_node("hunter", self._hunter_agent)
        graph.add_node("analogical_reasoner", self._analogical_reasoner)
        graph.add_node("skeptical_validator", self._skeptical_validator)
        graph.add_node("exploit_synthesizer", self._exploit_synthesizer)
        graph.add_node("self_evaluation", self._self_evaluation_agent)

        graph.add_edge(START, "hunter")
        graph.add_edge("hunter", "analogical_reasoner")
        graph.add_edge("analogical_reasoner", "skeptical_validator")

        graph.add_conditional_edges(
            "skeptical_validator",
            self._route_from_skeptic,
            {
                "rewrite": "hunter",
                "continue": "exploit_synthesizer",
                "terminate": END,
            },
        )

        graph.add_edge("exploit_synthesizer", "self_evaluation")

        graph.add_conditional_edges(
            "self_evaluation",
            self._route_from_self_eval,
            {
                "rewrite": "hunter",
                "approve": END,
                "terminate": END,
            },
        )

        return graph

    # ------------------------------------------------------------------
    # Node implementations
    # ------------------------------------------------------------------
    def _hunter_agent(self, state: Dict[str, Any]) -> Dict[str, Any]:
        config = self.agents_config.get("hunter", {})
        prompt = self._render_template(
            config.get("prompt", ""),
            {
                "contract_code": state.get("contract_code", ""),
                "contract_type": state.get("contract_type", "unknown"),
                "static_analysis_summary": self._format_static_analysis(state.get("static_analysis")),
                "previous_hypotheses": json.dumps(
                    state.get("shared_memory", {}).get("hypotheses", []), indent=2
                ),
                "feedback": "\n".join(state.get("shared_memory", {}).get("feedback", [])) or "None",
                "iteration": state.get("iteration", 0) + 1,
            },
        )

        response = self._invoke_llm(prompt, config.get("temperature", 0.8), config.get("model"))
        parsed = self._safe_json_loads(response)

        shared_memory = self._copy_shared_memory(state)
        hypotheses = self._extract_from_parsed(parsed, ["hypotheses", "ideas", "candidates"], default=[])
        shared_memory["hypotheses"] = hypotheses
        shared_memory["hunter_raw"] = response

        reports = list(state.get("agent_reports", []))
        reports.append(
            {
                "agent": "hunter",
                "role": "Hunter Agent",
                "temperature": config.get("temperature", 0.8),
                "prompt": prompt,
                "raw_response": response,
                "parsed": parsed,
            }
        )

        return {
            "shared_memory": shared_memory,
            "agent_reports": reports,
            "iteration": state.get("iteration", 0) + 1,
        }

    def _analogical_reasoner(self, state: Dict[str, Any]) -> Dict[str, Any]:
        config = self.agents_config.get("analogical_reasoner", {})
        shared_memory = self._copy_shared_memory(state)

        prompt = self._render_template(
            config.get("prompt", ""),
            {
                "contract_type": state.get("contract_type", "unknown"),
                "contract_summary": shared_memory.get("contract_summary")
                or self._summarize_contract(state.get("contract_code", "")),
                "previous_hypotheses": json.dumps(shared_memory.get("hypotheses", []), indent=2),
                "learned_patterns": json.dumps(shared_memory.get("learned_patterns", []), indent=2),
            },
        )

        response = self._invoke_llm(prompt, config.get("temperature", 0.65), config.get("model"))
        parsed = self._safe_json_loads(response)

        enhancements = self._extract_from_parsed(parsed, ["enhancements", "analysis", "hypotheses"], default=[])
        if enhancements:
            shared_memory["analogical_enhancements"] = enhancements
            shared_memory["hypotheses"] = enhancements
        shared_memory["analogical_raw"] = response

        reports = list(state.get("agent_reports", []))
        reports.append(
            {
                "agent": "analogical_reasoner",
                "role": "Analogical Reasoner",
                "temperature": config.get("temperature", 0.65),
                "prompt": prompt,
                "raw_response": response,
                "parsed": parsed,
            }
        )

        return {
            "shared_memory": shared_memory,
            "agent_reports": reports,
        }

    def _skeptical_validator(self, state: Dict[str, Any]) -> Dict[str, Any]:
        config = self.agents_config.get("skeptical_validator", {})
        shared_memory = self._copy_shared_memory(state)

        prompt = self._render_template(
            config.get("prompt", ""),
            {
                "contract_code": state.get("contract_code", ""),
                "hypotheses": json.dumps(shared_memory.get("hypotheses", []), indent=2),
                "static_analysis_summary": self._format_static_analysis(state.get("static_analysis")),
            },
        )

        response = self._invoke_llm(prompt, config.get("temperature", 0.35), config.get("model"))
        parsed = self._safe_json_loads(response)

        validated = self._extract_from_parsed(parsed, ["validated", "keep", "kept"], default=[])
        rejected = self._extract_from_parsed(parsed, ["rejected", "discarded"], default=[])
        decision = self._extract_decision(parsed, response)
        feedback = self._extract_feedback(parsed, response)

        shared_memory["validated_hypotheses"] = validated
        shared_memory["rejected_hypotheses"] = rejected
        shared_memory.setdefault("feedback", [])
        if feedback:
            shared_memory["feedback"].append(feedback)
        shared_memory["skeptic_raw"] = response
        shared_memory["skeptic_review"] = parsed

        reports = list(state.get("agent_reports", []))
        reports.append(
            {
                "agent": "skeptical_validator",
                "role": "Skeptical Validator",
                "temperature": config.get("temperature", 0.35),
                "prompt": prompt,
                "raw_response": response,
                "parsed": parsed,
                "decision": decision,
            }
        )

        update: Dict[str, Any] = {
            "shared_memory": shared_memory,
            "agent_reports": reports,
        }

        if decision == "rewrite":
            update["rewrite_count"] = state.get("rewrite_count", 0) + 1
        elif decision == "terminate":
            shared_memory.setdefault("final_assessment", {})
            shared_memory["final_assessment"].update(
                {
                    "status": "terminated",
                    "summary": feedback or "Terminated by skeptical validator.",
                    "confidence": 0.0,
                }
            )

        return update

    def _exploit_synthesizer(self, state: Dict[str, Any]) -> Dict[str, Any]:
        config = self.agents_config.get("exploit_synthesizer", {})
        shared_memory = self._copy_shared_memory(state)

        prompt = self._render_template(
            config.get("prompt", ""),
            {
                "contract_code": state.get("contract_code", ""),
                "validated_hypotheses": json.dumps(shared_memory.get("validated_hypotheses", []), indent=2),
            },
        )

        response = self._invoke_llm(prompt, config.get("temperature", 0.3), config.get("model"))
        parsed = self._safe_json_loads(response)

        scenarios = self._extract_from_parsed(parsed, ["scenarios", "exploits", "results"], default=[])
        shared_memory["exploit_scenarios"] = scenarios
        shared_memory["exploit_raw"] = response

        reports = list(state.get("agent_reports", []))
        reports.append(
            {
                "agent": "exploit_synthesizer",
                "role": "Exploit Synthesizer",
                "temperature": config.get("temperature", 0.3),
                "prompt": prompt,
                "raw_response": response,
                "parsed": parsed,
            }
        )

        return {
            "shared_memory": shared_memory,
            "agent_reports": reports,
        }

    def _self_evaluation_agent(self, state: Dict[str, Any]) -> Dict[str, Any]:
        config = self.agents_config.get("self_evaluation", {})
        shared_memory = self._copy_shared_memory(state)

        prompt = self._render_template(
            config.get("prompt", ""),
            {
                "exploit_scenarios": json.dumps(shared_memory.get("exploit_scenarios", []), indent=2),
                "validated_hypotheses": json.dumps(shared_memory.get("validated_hypotheses", []), indent=2),
                "feedback": "\n".join(shared_memory.get("feedback", [])) or "None",
            },
        )

        response = self._invoke_llm(prompt, config.get("temperature", 0.25), config.get("model"))
        parsed = self._safe_json_loads(response)

        decision = self._extract_decision(parsed, response, default="approve")
        feedback = self._extract_feedback(parsed, response)
        confidence = self._extract_confidence(parsed)

        shared_memory.setdefault("final_assessment", {})
        shared_memory["final_assessment"].update(
            {
                "status": "approved" if decision == "approve" else decision,
                "summary": feedback or shared_memory["final_assessment"].get("summary", ""),
                "confidence": confidence,
                "actions": self._extract_from_parsed(parsed, ["actions", "next_steps"], default=[]),
            }
        )
        if feedback:
            shared_memory.setdefault("feedback", []).append(feedback)
        shared_memory["self_eval_raw"] = response

        reports = list(state.get("agent_reports", []))
        reports.append(
            {
                "agent": "self_evaluation",
                "role": "Self-Evaluation Agent",
                "temperature": config.get("temperature", 0.25),
                "prompt": prompt,
                "raw_response": response,
                "parsed": parsed,
                "decision": decision,
            }
        )

        update: Dict[str, Any] = {
            "shared_memory": shared_memory,
            "agent_reports": reports,
        }

        if decision == "rewrite":
            update["rewrite_count"] = state.get("rewrite_count", 0) + 1

        return update

    # ------------------------------------------------------------------
    # Conditional routing helpers
    # ------------------------------------------------------------------
    def _route_from_skeptic(self, state: Dict[str, Any]) -> str:
        decision = self._latest_decision(state, "skeptical_validator")
        rewrite_count = state.get("rewrite_count", 0)

        if decision == "terminate":
            return "terminate"
        if decision == "rewrite" and rewrite_count < self.max_rewrites:
            return "rewrite"
        return "continue"

    def _route_from_self_eval(self, state: Dict[str, Any]) -> str:
        decision = self._latest_decision(state, "self_evaluation")
        rewrite_count = state.get("rewrite_count", 0)

        if decision == "terminate":
            return "terminate"
        if decision == "rewrite" and rewrite_count < self.max_rewrites:
            return "rewrite"
        return "approve"

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        resolved = Path(config_path) if config_path else self.DEFAULT_CONFIG_PATH
        try:
            with open(resolved, "r", encoding="utf-8") as fh:
                return yaml.safe_load(fh) or {}
        except FileNotFoundError:
            return {}

    def _initial_shared_memory(self) -> Dict[str, Any]:
        return {
            "hypotheses": [],
            "validated_hypotheses": [],
            "rejected_hypotheses": [],
            "exploit_scenarios": [],
            "feedback": [],
            "final_assessment": {},
        }

    def _render_template(self, template: str, variables: Dict[str, Any]) -> str:
        rendered = template or ""
        for key, value in variables.items():
            placeholder = f"{{{{{key}}}}}"
            rendered = rendered.replace(placeholder, str(value))
        return rendered

    def _format_static_analysis(self, data: Optional[Dict[str, Any]]) -> str:
        if not data:
            return "No static analysis data provided."
        try:
            return json.dumps(data, indent=2)
        except (TypeError, ValueError):
            return str(data)

    def _summarize_contract(self, contract_code: str) -> str:
        if not contract_code:
            return ""
        first_lines = "\n".join(contract_code.splitlines()[:40])
        return first_lines + ("\n..." if len(contract_code.splitlines()) > 40 else "")

    def _invoke_llm(self, prompt: str, temperature: float, model: Optional[str]) -> Any:
        if hasattr(self.llm_client, "query_llm"):
            return self.llm_client.query_llm(prompt, model=model or self.default_model, temperature=temperature)
        raise NotImplementedError(
            "llm_client must implement a public 'query_llm' method. "
            "Accessing private methods like '_call_llm' is not supported. "
            "Please update your llm_client to provide a public interface."
        )

    def _safe_json_loads(self, payload: Any) -> Any:
        if isinstance(payload, (dict, list)):
            return payload
        if not isinstance(payload, str):
            return payload
        text = payload.strip()
        if not text:
            return payload
        for candidate in (text, self._extract_json_substring(text)):
            if not candidate:
                continue
            try:
                return json.loads(candidate)
            except (json.JSONDecodeError, TypeError):
                continue
        return payload

    def _extract_json_substring(self, text: str) -> Optional[str]:
        first_brace = text.find("{")
        first_bracket = text.find("[")
        start_indices = [i for i in [first_brace, first_bracket] if i != -1]
        if not start_indices:
            return None
        start = min(start_indices)
        candidate = text[start:]
        end_brace = candidate.rfind("}")
        end_bracket = candidate.rfind("]")
        end_indices = [i for i in [end_brace, end_bracket] if i != -1]
        if not end_indices:
            return None
        end = max(end_indices) + 1
        return candidate[:end]

    def _extract_from_parsed(self, parsed: Any, keys: List[str], default: Any = None) -> Any:
        if isinstance(parsed, dict):
            for key in keys:
                if key in parsed:
                    return parsed[key]
        return default

    def _extract_decision(self, parsed: Any, raw: Any, default: str = "continue") -> str:
        if isinstance(parsed, dict):
            decision = parsed.get("decision") or parsed.get("status")
            if isinstance(decision, str):
                lowered = decision.lower()
                if lowered in {"rewrite", "revise"}:
                    return "rewrite"
                if lowered in {"terminate", "abort", "reject"}:
                    return "terminate"
                if lowered in {"approve", "continue", "proceed"}:
                    return "continue"
        if isinstance(raw, str):
            lowered = raw.lower()
            if "rewrite" in lowered or "revise" in lowered:
                return "rewrite"
            if any(word in lowered for word in ["abort", "terminate", "reject"]):
                return "terminate"
            if "approve" in lowered or "proceed" in lowered:
                return "continue"
        return default

    def _extract_feedback(self, parsed: Any, raw: Any) -> str:
        if isinstance(parsed, dict):
            for key in ["feedback", "notes", "summary", "reasoning"]:
                value = parsed.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        if isinstance(raw, str):
            return raw.strip()
        return ""

    def _extract_confidence(self, parsed: Any) -> float:
        if isinstance(parsed, dict):
            confidence = parsed.get("confidence")
            if isinstance(confidence, (int, float)):
                return float(confidence)
        return 0.5

    def _copy_shared_memory(self, state: Dict[str, Any]) -> Dict[str, Any]:
        return copy.deepcopy(state.get("shared_memory", self._initial_shared_memory()))

    def _latest_decision(self, state: Dict[str, Any], agent_name: str) -> str:
        for report in reversed(state.get("agent_reports", [])):
            if report.get("agent") == agent_name:
                decision = report.get("decision")
                if decision:
                    return decision
        return "continue"

