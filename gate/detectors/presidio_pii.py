"""Presidio-backed PII detection and input redaction for Bastion.Gate."""

import asyncio
from pathlib import Path
from typing import Literal

import yaml
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.predefined_recognizers import (
    CreditCardRecognizer,
    EmailRecognizer,
    PhoneRecognizer,
    UsSsnRecognizer,
)
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from pydantic import BaseModel, TypeAdapter

from detectors.base import DetectorSignal


PiiEntityType = Literal[
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "US_SSN",
]


class PiiEntityConfig(BaseModel):
    """One enabled Presidio entity type and its detector-owned threshold."""

    entity_type: PiiEntityType
    threshold: float


class PresidioPiiDetector:
    """Run configured Presidio recognizers off the async request event loop."""

    detector_name = "presidio_pii"

    def __init__(
        self,
        analyzer: AnalyzerEngine,
        anonymizer: AnonymizerEngine,
        entity_configs: list[PiiEntityConfig],
    ) -> None:
        self._analyzer = analyzer
        self._anonymizer = anonymizer
        self._entity_configs = entity_configs
        self._thresholds = {
            entity_config.entity_type: entity_config.threshold
            for entity_config in entity_configs
        }

    @property
    def analyzer(self) -> AnalyzerEngine:
        """Return the process-lifetime analyzer instance."""

        return self._analyzer

    @property
    def anonymizer(self) -> AnonymizerEngine:
        """Return the process-lifetime anonymizer instance."""

        return self._anonymizer

    @classmethod
    def from_yaml(cls, entities_path: Path) -> "PresidioPiiDetector":
        """Load entity configuration and initialize Presidio once at startup."""

        with entities_path.open(encoding="utf-8") as entities_file:
            raw_entity_configs = yaml.safe_load(entities_file)

        entity_configs = TypeAdapter(list[PiiEntityConfig]).validate_python(
            raw_entity_configs
        )
        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
            }
        )
        nlp_engine = provider.create_engine()
        registry = RecognizerRegistry(
            recognizers=[
                EmailRecognizer(),
                PhoneRecognizer(),
                CreditCardRecognizer(),
                UsSsnRecognizer(),
            ],
            supported_languages=["en"],
        )
        analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine,
            registry=registry,
            supported_languages=["en"],
        )
        return cls(
            analyzer=analyzer,
            anonymizer=AnonymizerEngine(),
            entity_configs=entity_configs,
        )

    async def scan(self, content: str) -> DetectorSignal:
        """Analyze and anonymize PII without blocking Gate's event loop."""

        return await asyncio.to_thread(self._scan_blocking, content)

    def _scan_blocking(self, content: str) -> DetectorSignal:
        """Apply per-entity thresholds after Presidio returns all candidates."""

        results = self._analyzer.analyze(
            text=content,
            entities=[entity_config.entity_type for entity_config in self._entity_configs],
            language="en",
        )
        accepted_results = [
            result
            for result in results
            if result.score >= self._thresholds[result.entity_type]
        ]
        entities = list(dict.fromkeys(result.entity_type for result in accepted_results))
        if not entities:
            return DetectorSignal(detector=self.detector_name)

        operators = {
            entity_type: OperatorConfig("replace", {"new_value": "[REDACTED]"})
            for entity_type in entities
        }
        anonymized = self._anonymizer.anonymize(
            text=content,
            analyzer_results=accepted_results,
            operators=operators,
        )
        return DetectorSignal(
            detector=self.detector_name,
            entities=entities,
            redacted_content=anonymized.text,
        )
