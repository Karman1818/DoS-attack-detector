# Exploratory Data Analysis & Notebooks

This directory is reserved for Jupyter notebooks used in exploratory analysis, threshold tuning, and machine-learning model evaluation.

## Guidelines

1. **Self-Contained Imports**: Use the installed `dos_detector` package (`from dos_detector import ...`) rather than ad-hoc `sys.path` hacks.
2. **Untracked Outputs**: Clear notebook cell outputs before committing to avoid leaking internal dataset rows or metadata.
3. **Small Samples**: When prototyping, load small truncated subsets of PCAPs/CSVs to prevent memory exhaustion.
