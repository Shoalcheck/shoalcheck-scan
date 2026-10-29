package types

import "testing"

// A ZERO OVER A CLUSTER WHOSE NODE TYPES DID NOT PRICE IS NOT A MEASUREMENT.
//
// The coverage question was asked of the resource kinds only: collected none, or refused some. A reading
// can collect every kind it asked for and still have no rate for the machines it found — an uncovered
// region, a machine type the table does not carry — and then "we looked and there is nothing to save" rests
// on a price table that could not price the cluster. This is M-88's fleet sentence one level down: nothing
// priceable does not read as free.
func TestDollarsAreAMeasurementForReading_AnUnpricedNodeTypeMakesTheZeroAnAbsence(t *testing.T) {
	complete := func() *AuditReport {
		return &AuditReport{
			Methodology: Methodology{CollectedKinds: []string{"pods", "nodes", "services"}},
			Summary:     Summary{EstimatedSavingsUSD: 0},
		}
	}

	if !DollarsAreAMeasurementForReading(complete()) {
		t.Fatalf("a complete reading with nothing cost-bearing has a MEASURED zero; this test would " +
			"otherwise be asserting the fix by taking a real result away")
	}

	withUnpricedPool := complete()
	withUnpricedPool.Architecture = &Architecture{UnpricedNodeTypes: []string{"Standard_D48s_v9"}}
	if DollarsAreAMeasurementForReading(withUnpricedPool) {
		t.Errorf("a reading whose node type resolved to no rate answers that its $0 is a measurement: " +
			"the pool's cost is unknown, so what could be saved on it is unknown too")
	}

	withFigure := withUnpricedPool
	withFigure.Summary.EstimatedSavingsUSD = 412
	if !DollarsAreAMeasurementForReading(withFigure) {
		t.Errorf("a positive total came from findings that priced and is real whatever else failed: the " +
			"asymmetry this file is built on must survive the fix")
	}

	withUnpricedStorage := complete()
	withUnpricedStorage.Architecture = &Architecture{UnpricedStorageClasses: []string{"fast-nvme"}}
	if DollarsAreAMeasurementForReading(withUnpricedStorage) {
		t.Errorf("a storage class with no rate is the same absence as a node type with no rate")
	}
}
