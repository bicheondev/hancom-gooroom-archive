# Gooroom applauncher Hancom source-lineage verification

- Source relationship valid: `true`
- Source lineage strictly validated: `true`
- ELF semantic match: `true`
- Normalized runtime ELF identity: `true`
- ELF differences limited to Build ID/debug-link metadata: `true`
- Non-ELF payload byte identity: `true`
- Raw ELF byte identity: `false`
- Full DEB byte identity: `false`
- Raw differing ELF bytes: `60`
- Differing ELF sections: `.gnu_debuglink, .note.gnu.build-id`

## Hashes

- Target DEB SHA-256: `97d4ad82497333615de5eea8fa4d64fd9538f000dccaee5acb1f6f26f44edc00`
- Rebuilt DEB SHA-256: `3c51a0dddfe9ac260a5c98b1817762f638b4e81542e1e8f65038ef10ba2dcae2`
- Target ELF SHA-256: `01f8fccd11542920cf603e5e9f4d4fbc32e27dc3c9cac64f653705bbaa1808e4`
- Rebuilt ELF SHA-256: `391bc503cfc7c840135c4187282980660bafe010a54a1e3d42b93b1a26555125`
- Normalized ELF SHA-256: `425909c5b144f89c6d2d85990d2fdd316da38d213e3b6644d8adc016e8a2c126`

Full byte identity is claimed only when the full DEB hashes are equal. 
The normalized ELF claim permits only the validated 20-byte GNU Build 
ID descriptor and its mechanically derived .gnu_debuglink payload.
