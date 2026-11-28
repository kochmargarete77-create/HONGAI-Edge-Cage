"""Validate a synthetic NDJSON fixture produced by the actual PowerShell helpers."""
import argparse
import json
from analyse_observation import read_bounded, summarize_bytes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True)
    args = parser.parse_args()
    result = summarize_bytes(read_bounded(args.fixture))
    assert result["evidenceProvenance"] == "SYNTHETIC_FIXED_FIXTURE"
    assert result["sampleCount"] == 2
    assert result["captureStructure"] == "COMPLETE_RECORD_SEQUENCE"
    assert result["coverage"]["tcpMetadata"]["notObservedSamples"] == 1
    assert result["fullEnvironmentAccepted"] is False
    assert result["officialClientReadCoverageCompleted"] is False
    print(json.dumps({"schema": "hongai.windows-observer-contract-test.v1", "source": "SYNTHETIC_FIXED_FIXTURE", "result": "PASS", "checks": 6, "liveCollectionExecuted": False}))


if __name__ == "__main__":
    main()
