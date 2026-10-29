"""Architecture import package: parsers -> normalize -> staged commit.

Never executes uploads; never touches authoritative records until an
explicit commit. Unknown kinds/zones/relations become warnings, not errors.
"""
