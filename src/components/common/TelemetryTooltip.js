import React from 'react';

/**
 * Custom Recharts tooltip with crisp theme-aware contrast and tabular numerals.
 */
const TelemetryTooltip = ({ active, payload, label, unitMap = {}, defaultUnit = '' }) => {
    if (!active || !payload || payload.length === 0) {
        return null;
    }

    return (
        <div className="chart-tooltip" role="status">
            {label && <div className="chart-tooltip-label">{label}</div>}
            <div className="chart-tooltip-items">
                {payload.map((entry, idx) => {
                    const key = entry.dataKey || entry.name || idx;
                    const unit = unitMap[entry.dataKey] ?? unitMap[entry.name] ?? defaultUnit;
                    const rawVal = entry.value;
                    const formatted =
                        typeof rawVal === 'number'
                            ? Number.isInteger(rawVal)
                                ? rawVal.toString()
                                : rawVal.toFixed(1)
                            : rawVal;

                    return (
                        <div key={key} className="chart-tooltip-row">
                            <span className="chart-tooltip-series">
                                <span
                                    className="chart-tooltip-dot"
                                    style={{ backgroundColor: entry.color || entry.fill || 'var(--primary-color)' }}
                                />
                                <span className="chart-tooltip-name">{entry.name}</span>
                            </span>
                            <span className="chart-tooltip-value tabular-nums">
                                {formatted}
                                {unit ? ` ${unit}`.trimEnd() : ''}
                            </span>
                        </div>
                    );
                })}
            </div>
        </div>
    );
};

export default TelemetryTooltip;

