# Miscellaneous Operational Workflow

1. Boundary Characterization: Probe allowed characters, length limits, and blocked keywords/builtins.
2. Primitive Construction:
   - Python: Traverse ().__class__.__base__.__subclasses__() to reach os._wrap_close or importlib.
   - Bash: Use wildcards (/???/??t), string slicing, or parameter expansion ($IFS).
3. Execution & Exfiltration: Execute read commands against target filesystem (cat flag.txt).
