# LLM.md - AI-Assisted Contribution Guidelines

This document outlines the requirements for contributions that involve AI assistance in this project.

## Assisted-by Tag Requirement

When AI tools are used during development, the source must be clearly documented so everyone can understand the extent of AI involvement in each submission. All code contributions involving AI assistance must include an `Assisted-by` tag using the following format:

```
Assisted-by: AGENT_NAME:MODEL_VERSION [TOOL1] [TOOL2]
```

### Format Specification

| Component | Description |
|-----------|-------------|
| `AGENT_NAME` | The name of the AI tool or framework used (e.g., Claude, OpenClaw, Copilot) |
| `MODEL_VERSION` | The specific model version (e.g., claude-3-opus, gemini-2.5-pro, k2p5) |
| `[TOOL1] [TOOL2]` | Optional: Additional specialized analysis tools used (e.g., coccinelle, sparse, smatch, clang-tidy) |

### Notes

- **Do not include** common everyday tools like git, gcc, make, or text editors
- Only list specialized analysis or transformation tools that significantly contributed to the code
- Multiple `Assisted-by` tags may be used if different AI tools were used for different parts of the contribution

### Examples

**Using Claude with coccinelle and sparse:**
```
Assisted-by: Claude:claude-3-opus coccinelle sparse
```

**Using OpenClaw with no additional tools:**
```
Assisted-by: OpenClaw:k2p5
```

**Using GitHub Copilot:**
```
Assisted-by: Copilot:gpt-4o
```

**Multiple AI tools used:**
```
Assisted-by: Claude:claude-3-opus clang-tidy
Assisted-by: OpenClaw:gemini-3.1-pro-preview
```

## Where to Include

Add the `Assisted-by` tag(s) at the end of your commit message, after the sign-off line (if present):

```
Fix memory leak in request handler

This patch fixes a use-after-free bug in the async request handler
that could occur during rapid create/destroy cycles.

Signed-off-by: John Doe <john@example.com>
Assisted-by: Claude:claude-3-opus coccinelle sparse
```

## Why This Matters

1. **Transparency**: Maintainers and reviewers should know when AI has assisted in code creation
2. **Attribution**: Proper credit for AI contributions helps track the evolution of development practices
3. **Quality Assurance**: Understanding AI involvement helps set appropriate review standards
4. **Audit Trail**: Creates a clear record for future reference and analysis

## Scope

This requirement applies to:
- Code changes (any language)
- Configuration files
- Build scripts
- Documentation (if substantially AI-generated)

This requirement does **not** apply to:
- Minor typo fixes
- Pure formatting changes
- Changes made entirely without AI assistance
